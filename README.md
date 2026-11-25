# BANKSHIELD AI — CyberVault AI

A college-project prototype demonstrating simulated employee activity monitoring, explainable risk scoring, DLP pattern detection, incident creation, and simulated containment. **Synthetic data only; not a real banking security product.**

## Responsive interface
The dashboard includes desktop/tablet/mobile layouts. On narrow screens, use the **☰ menu** in the top bar to open the navigation drawer; tap the dimmed backdrop or press **Esc** to close it. Tables scroll horizontally on small screens, and cards/forms stack into a single column for phone-width screens.

## Run on Windows

1. Install Python 3.10+ from https://python.org (check **Add Python to PATH** during install).
2. Extract this ZIP and open the `bankshield_ai` folder in VS Code.
3. Open VS Code Terminal (`Terminal → New Terminal`) and run:

```powershell
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
py app.py
```
4. Visit **http://127.0.0.1:5000** in your browser.

If `py` is unavailable, try `python` instead.

## Demo flow (3–5 minutes)
- Dashboard: explain monitoring summary and event feed.
- Live Monitoring: use search and risk filters; generate a normal activity.
- Attack Simulator: run **Bulk data extraction** to create a critical event and incident; show reasons and simulated response.
- DLP: paste the sample below and click Scan.
- Investigations: resolve an incident to demonstrate workflow.

Sample DLP text (fake):
```
Email: demo.person@example.test
Phone: 9876543210
Account: AC123456789012
PAN-like: ABCDE1234F
Aadhaar-like: 1234 5678 9012
password: sample-not-real-123
```

## Detection notes
Risk scoring is explainable rule-based logic, capped at 100. This prototype intentionally avoids external AI services, so it does not claim a trained model is running. Scenario-triggered activity and response are simulated. Data is persisted locally in `bankshield.db` (created on first run). Use **Settings → Reset demo data** to clear generated events/incidents.

## GitHub quick start
Create a GitHub repository named `BANKSHIELD-AI`, then in the project terminal:
```bash
git init
git add .
git commit -m "Initial BANKSHIELD AI prototype"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/BANKSHIELD-AI.git
git push -u origin main
```
Replace `YOUR-USERNAME` with your GitHub username. Never commit the local database or secrets.
