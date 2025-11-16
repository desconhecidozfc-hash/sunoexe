# Quick Install Guide

## One-Time Setup Script
Run the following block to install all system packages, prepare directories, and clone the repo into `/srv/action-runtime/app`.

```bash
sudo apt update && \
  sudo apt install -y python3 python3-venv python3-pip git nodejs npm chromium cloudflared rsync && \
  sudo npm install -g pm2 && \
  sudo mkdir -p /srv/action-runtime/{app,fsroot,sessions,browser/context,manus-pages} && \
  sudo chown -R "$USER":"$USER" /srv/action-runtime && \
  git clone https://github.com/desconhecidozfc-hash/sunoexe.git /srv/action-runtime/app
```

## Fast Python + Node Prep
Create the virtual environment, install Python requirements, and pull Node modules in one go.
```bash
cd /srv/action-runtime/app/srvaction-runtime && \
  python3 -m venv .venv && \
  source .venv/bin/activate && \
  pip install --upgrade pip && \
  pip install -r ../requirements.txt && \
  cd .. && npm install
```

## Launch the API Immediately
Use this single command to activate the venv and start Uvicorn.
```bash
cd /srv/action-runtime/app/srvaction-runtime && \
  source .venv/bin/activate && \
  uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Quick Port Exposure
Open the firewall and optionally start a Cloudflare tunnel.
```bash
sudo ufw allow 8000/tcp && cloudflared tunnel --url http://127.0.0.1:8000
```

## Update Everything Later (Minimal Steps)
Pull latest code, refresh requirements inside the existing venv, and restart the server.
```bash
cd /srv/action-runtime/app && \
  git pull && \
  cd srvaction-runtime && \
  source .venv/bin/activate && \
  pip install --upgrade -r ../requirements.txt && \
  uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Quick Health Test
Confirm the API is live.
```bash
curl http://127.0.0.1:8000/health
```
