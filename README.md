# SentinelAI

AI-Powered SOC Alert Triage & Incident Correlation Platform.

## 1. Problem
A Tier-1 SOC analyst receives thousands of raw security alerts daily. The problem isn't finding alerts, but rather finding which alerts belong together. Analysts spend too much time manually correlating events, resulting in high Mean Time To Triage (MTTT) and alert fatigue.

## 2. Solution
SentinelAI ingests raw alerts, deduplicates them, builds behavioral profiles for users and IPs, correlates related alerts into high-fidelity incidents, calculates explainable risk scores, maps behavior to MITRE ATT&CK techniques, and generates AI-driven investigation summaries. The final decision remains with a human analyst.

## 3. Architecture
- **Backend**: FastAPI (Python), SQLAlchemy, SQLite (Dev), NetworkX, Scikit-learn
- **AI**: Google Gemini 1.5 Flash (via python SDK)
- **Frontend**: Next.js, Tailwind CSS, Recharts, Lucide Icons

## 4. Installation & Running Locally

1. Setup environment variables:
   Copy `.env.example` to `.env` in the root folder and add your `GEMINI_API_KEY`.

2. Generate the dataset:
   ```bash
   cd backend
   python scripts/generate_dataset.py
   ```

3. Run the backend:
   ```bash
   cd backend
   pip install -r requirements.txt
   uvicorn app.main:app --reload
   ```

4. Run the frontend:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

## 5. End-to-End Workflow

1. Open the Dashboard (http://localhost:3000)
2. Click **Run AI Triage**. The pipeline will:
   - Ingest 3,000 synthetic raw alerts.
   - Deduplicate alerts within time windows.
   - Profile all users and IPs.
   - Correlate events using 12 different strategies (e.g. brute force, impossible travel).
   - Score the risk of incidents.
   - Map incidents to MITRE ATT&CK.
   - Call Gemini to summarize the incidents.
3. Review the high-priority incidents in the dashboard.
4. Open an incident, review the AI investigation brief and event sequence.
5. Provide a human Analyst Review (Confirm, False Positive, Investigate).

## 6. Evaluation Methodology
The synthetic data generator embeds known attack scenarios and marks them in a hidden ground truth file. The pipeline is evaluated on:
- Alert Reduction Rate (e.g., 3,000 alerts -> 15 incidents)
- Precision & Recall
- False Positive Rate

*Note: The LLM does NOT see the ground truth; it only sees the correlated evidence from the deterministic pipeline.*
