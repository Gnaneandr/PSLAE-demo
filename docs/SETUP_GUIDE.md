# SETUP_GUIDE
Requirements: Python 3.10+; packages `pycryptodome` (AES-CTR in the audited ACE stand-in) and `pytest`. No network is needed at run time.

## Windows (PowerShell)
```powershell
cd PSLAE_DEMO
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope Process Bypass
python -m pip install --upgrade pip
pip install -r requirements.txt
python demo.py list
python -m pytest -q tests
```
## Linux / macOS
```bash
cd PSLAE_DEMO && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
python3 demo.py list && python3 -m pytest -q tests
```
## Scyther
`scyther/bin/scyther-linux` is a Linux binary. On Windows download the Windows build from https://github.com/cascremers/scyther and run `python demo.py scyther --exe "C:\Tools\scyther\scyther-w32.exe"` (or set `SCYTHER_EXE`). Without a binary the command prints a clear message and the test is skipped.

## Verified status
Everything above was executed on Linux in a clean virtual environment. **Windows was not available; the Windows commands are unverified** (they use only portable Python).

## Dashboard
`pip install -r requirements-ui.txt` then `streamlit run app.py` (http://localhost:8501). Tested here: server start + automated page/button test; not tested: Windows, projector display.
