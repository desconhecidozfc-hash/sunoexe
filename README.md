# Action Runtime Server

## Overview
Action Runtime Server is a FastAPI service that exposes sandboxed file management, shell execution, browser automation, deployment helpers, and Manus page generation endpoints. Follow these steps to install it on a Linux VPS.

## System Packages
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git nodejs npm chromium cloudflared rsync
sudo npm install -g pm2
```

## Directory Layout
```bash
sudo mkdir -p /srv/action-runtime/{app,fsroot,sessions,browser/context,manus-pages}
sudo chown -R "$USER":"$USER" /srv/action-runtime
```

## Clone the Repository
```bash
cd /srv/action-runtime/app
git clone https://github.com/<your-org>/<your-repo>.git .
```

### Already cloned elsewhere?
Create a clean directory and clone again without touching the existing checkout.
```bash
mkdir -p /srv/action-runtime/app-new
cd /srv/action-runtime/app-new
git clone https://github.com/<your-org>/<your-repo>.git .
```
Switch between folders (`app` vs. `app-new`) depending on which install you want to run.

### Need a second working copy with the same Git URL?
If you already cloned the repository (for example, the Bitcoin URL) but want a fresh copy without deleting the first folder, use a unique target directory name during `git clone`.
```bash
mkdir -p /srv/action-runtime/app-second
git clone https://github.com/<your-org>/<your-repo>.git /srv/action-runtime/app-second
```
You can now work from `/srv/action-runtime/app-second` while keeping the original checkout intact.

## Python Environment
```bash
cd /srv/action-runtime/app/srvaction-runtime
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r ../requirements.txt
```

## Node.js Utilities
```bash
cd /srv/action-runtime/app
npm install
pm2 -v
```
Run `npm install` inside each Next.js project before invoking `deploy_apply_deployment` with `kind: nextjs`.

## Browser Automation Data
```bash
mkdir -p /srv/action-runtime/browser/context
```

## Start the Server
```bash
cd /srv/action-runtime/app/srvaction-runtime
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Managed option with PM2:
```bash
pm2 start "uvicorn app.main:app --host 0.0.0.0 --port 8000" --name action-runtime
pm2 save
```

## Expose Network Ports
```bash
sudo ufw allow 8000/tcp
```
Optional secure tunnel:
```bash
cloudflared tunnel --url http://127.0.0.1:8000
```

## Update from GitHub
```bash
cd /srv/action-runtime/app
git pull
cd srvaction-runtime
source .venv/bin/activate
pip install -r ../requirements.txt
```

### Update requirements inside the existing virtual environment (no reclone)
Use this flow when the repository content is already current but new dependencies were added (for example, after `requirements.txt` changed) and you only need to refresh the Python environment.
```bash
cd /srv/action-runtime/app/srvaction-runtime
source .venv/bin/activate
pip install --upgrade pip
pip install --upgrade -r ../requirements.txt
deactivate
```
Re-activate `.venv` whenever you need to run the server again:
```bash
cd /srv/action-runtime/app/srvaction-runtime
source .venv/bin/activate
```

## Health Check
```bash
curl http://127.0.0.1:8000/health
```
A successful response returns `{"success": true, "data": {"status": "ok"}}`.
