#!/usr/bin/env python3
# made by:    _    ____   ____    _    _   _  ____ _____ _     ___
#▄████▄ █████▄  ▄█████ ▄████▄ ███  ██  ▄████  ██████ ██     ▄████▄
#██▄▄██ ██▄▄██▄ ██     ██▄▄██ ██ ▀▄██ ██  ▄▄▄ ██▄▄   ██     ██  ██
#██  ██ ██   ██ ▀█████ ██  ██ ██   ██  ▀███▀  ██▄▄▄▄ ██████ ▀████▀
# --------------------------------------------------------------------- 

import os
from pathlib import Path

# ================= CONFIG =================
APP_NAME = "EVA"
APP_VERSION = "3.1"
GITHUB_REPO = "arcangel0/EVA"
PYPI_PACKAGE = "eva-exploit"
API_ENDPOINT = "NOT_SET" # <--- change to your desired endpoint if needed
G4F_MODEL="gpt-oss-120b"   
G4F_URL="https://api.gpt4free.workers.dev/api/novaai/chat/completions"
OLLAMA_MODEL = "ALIENTELLIGENCE/whiterabbitv2" # recommended ollama model
SEARCHVULN_MODEL = "gpt-oss:120b-cloud"
SEARCVULN_URL = "https://ollama.com/api/chat"
OLLAMA_API_KEY = "NOT_SET" # your ollama api key
OPENAI_API_KEY = "NOT_SET" # openai key
ANTHROPIC_API_KEY = "NOT_SET" #anthropic api key 
GEMINI_API_KEY = "NOT_SET" # your gemini key
ANTHROPIC_MODEL = "claude-3-5-sonnet-latest"
GEMINI_MODEL = "gemini-2.0-flash"
OLLAMA_CLOUD_TIMEOUT = 45
CONFIG_DIR = Path.home() / "EVA_data" # Path to save EVA files
SESSIONS_DIR = CONFIG_DIR / "sessions"
REPORTS_DIR = CONFIG_DIR / "reports"
MAPS_DIR = CONFIG_DIR / "attack_maps"
TERMS_ACCEPTEDTHING = CONFIG_DIR / ".confirm"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
MAPS_DIR.mkdir(parents=True, exist_ok=True)
username = os.getlogin()
MAX_RETRIES = 10 ### maximum retries for fetching requests
RETRY_DELAY = 10 ### delay between requests to avoid rate limit error

# All sessions will be stored on $HOME/.config/eva/sessions/*.json
