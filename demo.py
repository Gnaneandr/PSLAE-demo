#!/usr/bin/env python3
"""PSLAE research demonstration entry point:  python demo.py list | overview | registration | ake1 | ake2 | ake3 | session-key | full | parameters |
packet-breakdown | operations | security | scyther | svo | performance | traceability | tests | menu | help"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from demo.cli import main
if __name__ == "__main__":
    sys.exit(main())
