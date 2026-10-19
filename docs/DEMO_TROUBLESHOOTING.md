# DEMO_TROUBLESHOOTING
| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: Crypto` | pycryptodome missing | `pip install -r requirements.txt` (inside the activated venv) |
| PowerShell blocks `Activate.ps1` | execution policy | `Set-ExecutionPolicy -Scope Process Bypass` |
| `python demo.py scyther` says binary not found | the bundled binary is Linux-only | download Scyther for your OS; `--exe PATH` or `SCYTHER_EXE` |
| Scyther prints nothing / unexpected flags | different Scyther build | check `scyther --help`; the audited flags are `-r 100 -m 0 -A` |
| Output differs between runs | `--random` used | omit it (default seed 2024) or pass `--seed N` |
| `BrokenPipeError` when piping into `head` | pipe closed early | harmless |
| A demo shows `ACCEPT` for an attack | the code really accepted it | that is a reported weakness (see KNOWN_LIMITATIONS); do not change the code to hide it |
| `tests` fail after editing `src/` | integrity test | `src/` must stay identical to the checksums in `SRC_SHA256.txt`; restore the original audited `src/` files |
| Secrets appear in output | `--reveal-secrets` set | omit it |
| Menu in a non-interactive shell | no stdin | `python demo.py menu --script 1,7,9,11,0` |
