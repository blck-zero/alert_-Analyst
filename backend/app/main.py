"""Main FastAPI Application."""
import os
import uuid
import time
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.config import settings
from app.database.database import engine, get_db, Base
from app.schemas.schemas import AlertBase, IncidentBase, IncidentDetail, TriageRunResponse, AnalystReviewCreate, MetricsResponse

# Import models
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.triage_run import TriageRun
from app.models.user_profile import UserProfile
from app.models.ip_profile import IPProfile
from app.models.analyst_review import AnalystReview

# Import services
from app.services import ingestion, normalization, deduplication, correlation, risk_scoring, user_behavior, ip_behavior, mitre_mapping, ai_summarizer, evaluation

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="SentinelAI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"status": "ok", "service": "SentinelAI"}


@app.post("/api/alerts/upload")
def upload_alerts(db: Session = Depends(get_db)):
    """Ingest alerts from the dataset (simulates upload)."""
    count = ingestion.ingest_alerts(db)
    return {"message": f"Ingested {count} alerts"}


@app.get("/api/alerts", response_model=list[AlertBase])
def get_alerts(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    alerts = ingestion.get_all_alerts(db, skip=skip, limit=limit)
    return alerts


def _run_triage_pipeline(run_id: str):
    """Background task to run the complete pipeline."""
    # Get a fresh session for the background task
    from app.database.database import SessionLocal
    db = SessionLocal()
    
    try:
        run = db.query(TriageRun).filter(TriageRun.run_id == run_id).first()
        if not run:
            return
            
        start_time = time.time()
        
        # 1. Normalization
        run.current_stage = "normalizing"
        run.progress_pct = 10.0
        db.commit()
        normalization.normalize_alerts(db)
        
        # 2. Deduplication
        run.current_stage = "deduplicating"
        run.progress_pct = 20.0
        db.commit()
        orig, deduped = deduplication.deduplicate_alerts(db)
        run.duplicate_alerts_removed = deduped
        run.total_alerts_input = orig
        
        # 3. User Behavior Profiling
        run.current_stage = "user_profiling"
        run.progress_pct = 30.0
        db.commit()
        user_behavior.build_user_profiles(db)
        
        # 4. IP Behavior Profiling
        run.current_stage = "ip_profiling"
        run.progress_pct = 40.0
        db.commit()
        ip_behavior.build_ip_profiles(db)
        
        # 5. Correlation
        run.current_stage = "correlating"
        run.progress_pct = 50.0
        db.commit()
        incidents = correlation.correlate_alerts(db)
        run.incidents_created = len(incidents)
        
        # 6. Risk Scoring
        run.current_stage = "risk_scoring"
        run.progress_pct = 60.0
        db.commit()
        risk_scoring.score_all_incidents(db)
        
        # 7. MITRE Mapping
        run.current_stage = "mitre_mapping"
        run.progress_pct = 70.0
        db.commit()
        mitre_mapping.map_all_incidents(db)
        
        # 8. AI Summarization
        run.current_stage = "ai_summarization"
        run.progress_pct = 80.0
        db.commit()
        ai_summarizer.generate_summaries_for_incidents(db)
        
        # 9. Evaluation
        run.current_stage = "evaluation"
        run.progress_pct = 95.0
        db.commit()
        evaluation.evaluate_triage_run(db, run)
        
        # Finish
        run.status = "completed"
        run.current_stage = "done"
        run.progress_pct = 100.0
        run.completed_at = datetime.now(timezone.utc)
        run.processing_time_seconds = time.time() - start_time
        
        db.commit()
        
    except Exception as e:
        run.status = "failed"
        run.error_message = str(e)
        db.commit()
    finally:
        db.close()


@app.post("/api/triage/run", response_model=TriageRunResponse)
def run_triage(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Start the AI Triage pipeline."""
    run_id = f"RUN-{uuid.uuid4().hex[:8]}"
    
    # Initialize run in DB
    run = TriageRun(
        run_id=run_id,
        status="processing",
        current_stage="starting",
        progress_pct=0.0
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    
    # Send to background
    background_tasks.add_task(_run_triage_pipeline, run_id)
    
    return run


@app.get("/api/triage/{run_id}", response_model=TriageRunResponse)
def get_triage_status(run_id: str, db: Session = Depends(get_db)):
    run = db.query(TriageRun).filter(TriageRun.run_id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@app.get("/api/incidents", response_model=list[IncidentBase])
def get_incidents(db: Session = Depends(get_db)):
    return db.query(Incident).order_by(Incident.risk_score.desc()).all()


@app.get("/api/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/api/incidents/{incident_id}/review")
def review_incident(incident_id: str, review: AnalystReviewCreate, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    new_review = AnalystReview(
        incident_id=incident_id,
        decision=review.decision,
        notes=review.notes
    )
    
    incident.status = review.decision
    
    db.add(new_review)
    db.commit()
    return {"status": "success"}


@app.get("/api/metrics", response_model=MetricsResponse)
def get_metrics(db: Session = Depends(get_db)):
    # Get the latest completed run
    run = db.query(TriageRun).filter(TriageRun.status == "completed").order_by(TriageRun.id.desc()).first()
    
    total_alerts = db.query(Alert).count()
    incidents = db.query(Incident).all()
    
    crit = sum(1 for i in incidents if i.severity == "critical")
    high = sum(1 for i in incidents if i.severity == "high")
    med = sum(1 for i in incidents if i.severity == "medium")
    low = sum(1 for i in incidents if i.severity == "low")
    
    return {
        "total_alerts": total_alerts,
        "total_incidents": len(incidents),
        "critical_incidents": crit,
        "high_incidents": high,
        "medium_incidents": med,
        "low_incidents": low,
        "mttt_reduction_pct": 85.5,  # Mocked for UI, in a real scenario would calculate based on AnalystReview table
        "false_positive_rate": run.false_positive_rate if run else 0.0,
        "precision": run.precision if run else 0.0,
        "recall": run.recall if run else 0.0,
        "f1_score": run.f1_score if run else 0.0,
        "alert_reduction": run.alert_reduction_rate if run else 0.0
    }

@app.get("/api/correlation-graph")
def get_correlation_graph(db: Session = Depends(get_db)):
    return correlation.build_correlation_graph(db)

@app.get("/api/users")
def get_users(db: Session = Depends(get_db)):
    users = db.query(UserProfile).order_by(UserProfile.risk_level.desc()).all()
    return users

@app.get("/api/users/{username}")
def get_user(username: str, db: Session = Depends(get_db)):
    user = db.query(UserProfile).filter(UserProfile.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.get("/api/ips")
def get_ips(db: Session = Depends(get_db)):
    ips = db.query(IPProfile).order_by(IPProfile.risk_level.desc()).all()
    return ips

@app.get("/api/ips/{ip}")
def get_ip(ip: str, db: Session = Depends(get_db)):
    profile = db.query(IPProfile).filter(IPProfile.ip_address == ip).first()
    if not profile:
        raise HTTPException(status_code=404, detail="IP not found")
    return profile
