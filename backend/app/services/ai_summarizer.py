"""
AI Summarization Service using Google Gemini.

Generates concise, evidence-based investigation summaries for correlated incidents.
Strictly instructed NOT to invent evidence or definitively declare attacks.
"""

import json
import logging
from typing import Dict, List, Optional
import google.generativeai as genai
from sqlalchemy.orm import Session
from app.models.incident import Incident
from app.models.alert import Alert
from app.config import settings

logger = logging.getLogger(__name__)

# Configure Gemini
if settings.GEMINI_API_KEY:
    genai.configure(api_key=settings.GEMINI_API_KEY)
    
_MODEL_NAME = "gemini-1.5-flash"  # Use a fast model for summaries


def generate_summaries_for_incidents(db: Session, limit: int = 20) -> int:
    """Generate AI summaries for incidents that don't have one yet."""
    if not settings.GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set. Skipping AI summarization.")
        return 0

    incidents = (
        db.query(Incident)
        .filter(Incident.ai_summary.is_(None))
        .order_by(Incident.risk_score.desc())
        .limit(limit)
        .all()
    )

    count = 0
    for incident in incidents:
        try:
            _generate_single_summary(db, incident)
            count += 1
        except Exception as e:
            logger.error(f"Failed to generate summary for {incident.incident_id}: {e}")

    db.commit()
    return count


def _generate_single_summary(db: Session, incident: Incident):
    """Generate a summary for a single incident."""
    
    # Get a sample of alerts for evidence (up to 10)
    alerts = (
        db.query(Alert)
        .join(Alert.incident_alerts)
        .filter(Alert.incident_alerts.any(incident_id=incident.incident_id))
        .order_by(Alert.timestamp)
        .limit(10)
        .all()
    )
    
    alert_samples = []
    for a in alerts:
        alert_samples.append({
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "event_type": a.event_type,
            "source_ip": a.source_ip,
            "username": a.username,
            "message": a.message
        })

    # Prepare the context payload
    context = {
        "incident_id": incident.incident_id,
        "correlation_type": incident.correlation_type,
        "risk_score": incident.risk_score,
        "severity": incident.severity,
        "alert_count": incident.alert_count,
        "affected_users": incident.affected_users,
        "source_ips": incident.source_ips,
        "affected_assets": incident.affected_assets,
        "mitre_technique": incident.mitre_technique_name,
        "event_sequence": incident.event_sequence[:20] if incident.event_sequence else [],
        "sample_alerts": alert_samples
    }

    prompt = f"""
    You are an expert SOC Level 3 analyst. Review the following security incident evidence.
    
    Incident Evidence:
    {json.dumps(context, indent=2)}
    
    INSTRUCTIONS:
    1. Do NOT invent or hallucinate any evidence, IPs, usernames, or event counts.
    2. Do NOT declare that an attack definitively occurred. Use phrases like "Suspicious activity", "Potential behavior", "Evidence suggests", or "Requires review".
    3. Clearly distinguish between hard evidence and your inference.
    4. Provide plausible benign explanations (e.g., misconfiguration, shared IP, testing).
    
    Respond STRICTLY with a valid JSON object matching this schema:
    {{
        "summary": "1-2 paragraph executive summary",
        "key_evidence": ["list of 3-5 factual evidence points"],
        "possible_explanation": "What this might be (both malicious and benign possibilities)",
        "mitre_explanation": "Why this maps to the MITRE technique (if applicable)",
        "recommended_investigation_steps": ["list of 3-5 specific steps the human analyst should take"],
        "confidence": "high|medium|low",
        "limitations": ["list of blind spots or missing context"]
    }}
    """

    try:
        model = genai.GenerativeModel(_MODEL_NAME)
        # Using generation config to force JSON output if supported, otherwise rely on prompt
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        
        result_text = response.text
        # Sometimes models wrap JSON in markdown blocks even when told not to
        if result_text.startswith("```json"):
            result_text = result_text.split("```json")[1].split("```")[0].strip()
        elif result_text.startswith("```"):
            result_text = result_text.split("```")[1].strip()
            
        result = json.loads(result_text)
        
        incident.ai_summary = result.get("summary")
        incident.ai_key_evidence = result.get("key_evidence", [])
        incident.ai_possible_explanation = result.get("possible_explanation")
        incident.ai_mitre_explanation = result.get("mitre_explanation")
        incident.ai_investigation_steps = result.get("recommended_investigation_steps", [])
        incident.ai_confidence = result.get("confidence", "low")
        incident.ai_limitations = result.get("limitations", [])
        
    except Exception as e:
        logger.error(f"Error calling Gemini API: {e}")
        # Fallback to basic summary if API fails
        incident.ai_summary = f"Automated correlation identified {incident.alert_count} alerts matching a {incident.correlation_type} pattern."
        incident.ai_key_evidence = [f"Alert count: {incident.alert_count}", f"Source IPs: {incident.source_ips}"]
        incident.ai_possible_explanation = "Requires manual investigation."
        incident.ai_investigation_steps = ["Review raw logs", "Check user baseline"]
        incident.ai_confidence = "low"
        incident.ai_limitations = ["AI summarization failed"]

