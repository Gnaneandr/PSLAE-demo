#!/usr/bin/env bash
# Starts the panel dashboard (Linux/macOS). Open http://localhost:8501
cd "$(dirname "$0")" && streamlit run app.py --server.headless false --browser.gatherUsageStats false
