@echo off
REM Starts the panel dashboard (Windows). Activate the venv first. Opens http://localhost:8501
cd /d "%~dp0"
streamlit run app.py --browser.gatherUsageStats false
