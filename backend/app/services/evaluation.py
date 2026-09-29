"""
Evaluation metrics service.
Calculates performance metrics against ground truth.
"""

from typing import Dict
from sqlalchemy.orm import Session
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.triage_run import TriageRun


def evaluate_triage_run(db: Session, run: TriageRun) -> Dict:
    """
    Evaluate the triage run against ground truth labels.
    Calculates Precision, Recall, F1, and Alert Reduction.
    """
    # Get all alerts that were marked malicious in ground truth
    malicious_alerts = db.query(Alert).filter(Alert.is_malicious == True).all()
    benign_alerts = db.query(Alert).filter(Alert.is_malicious == False).all()
    
    malicious_ids = set(a.alert_id for a in malicious_alerts)
    benign_ids = set(a.alert_id for a in benign_alerts)
    
    # Get all alerts that were included in ANY incident
    incidents = db.query(Incident).all()
    alert_ids_in_incidents = set()
    for inc in incidents:
        if hasattr(inc, '_alert_ids') and inc._alert_ids:
            alert_ids_in_incidents.update(inc._alert_ids)
        else:
            # Fallback if _alert_ids isn't populated (e.g. loaded from DB)
            alerts = db.query(Alert).join(Alert.incident_alerts).filter(Alert.incident_alerts.any(incident_id=inc.incident_id)).all()
            alert_ids_in_incidents.update(a.alert_id for a in alerts)
            
    # Calculate True Positives (malicious alerts that made it into an incident)
    tp = len(malicious_ids.intersection(alert_ids_in_incidents))
    
    # Calculate False Positives (benign alerts that made it into an incident)
    fp = len(benign_ids.intersection(alert_ids_in_incidents))
    
    # Calculate False Negatives (malicious alerts that did NOT make it into an incident)
    fn = len(malicious_ids) - tp
    
    # Calculate metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    total_alerts = len(malicious_alerts) + len(benign_alerts)
    fpr = fp / len(benign_alerts) if len(benign_alerts) > 0 else 0.0
    
    # Reduction rate
    reduction_rate = 1.0 - (len(incidents) / total_alerts) if total_alerts > 0 else 0.0
    
    # Update run object
    run.true_positives = tp
    run.false_positives = fp
    run.false_negatives = fn
    run.precision = precision
    run.recall = recall
    run.f1_score = f1
    run.false_positive_rate = fpr
    run.alert_reduction_rate = reduction_rate
    
    db.commit()
    
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "reduction_rate": reduction_rate
    }
