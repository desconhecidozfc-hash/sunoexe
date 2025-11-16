# Action Runtime Server Installation

## System packages
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git nodejs npm chromium cloudflared rsync
sudo npm install -g pm2
```

## Directory layout
```bash
sudo mkdir -p /srv/action-runtime/{app,fsroot,sessions,browser/context,manus-pages}
sudo chown -R "$USER":"$USER" /srv/action-runtime
```

## Clone the repository
```bash
cd /srv/action-runtime/app
git clone https://github.com/desconhecidozfc-hash/sunoexe
```

## Python environment
```bash
cd /srv/action-runtime/app/srvaction-runtime
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Node.js and deployment helpers
```bash
# Required only for deployment commands such as deploy_apply_deployment
npm install
pm2 -v  # confirm availability for process management
```
Run `npm install` again inside each Next.js project when deploy_apply_deployment triggers `npm install`, `npm run build`, and `pm2 start`.

## Browser automation data
```bash
mkdir -p /srv/action-runtime/browser/context
```

## Start the server
```bash
cd /srv/action-runtime/app/srvaction-runtime
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Use PM2 for a managed process:
```bash
pm2 start "uvicorn app.main:app --host 0.0.0.0 --port 8000" --name action-runtime
pm2 save
```

## Expose network ports
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
pip install -r requirements.txt
```

## Test the API
```bash
curl http://127.0.0.1:8000/health
```
A successful response returns `{"success": true, "data": {"status": "ok"}}`.
