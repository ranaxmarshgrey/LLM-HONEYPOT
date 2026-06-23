# Deployment Guide — Adaptive LLM-Powered Honeypot

## 1. Cloud VM — Choose a Provider

| Provider | Plan | Cost | Notes |
|----------|------|------|-------|
| **Oracle Cloud** | VM.Standard.A1.Flex (ARM) | **Free forever** | Best for students. 1 OCPU, 6 GB RAM. Ubuntu 22.04 image available. |
| **Google Cloud** | e2-micro | **Free tier** (1 yr) | 1 vCPU, 1 GB RAM. Enough but tight. |
| **DigitalOcean** | Basic Droplet | $4–6/month | Easiest setup. Use referral credits. |
| **AWS EC2** | t2.micro | **Free tier** (1 yr) | 1 vCPU, 1 GB RAM. More setup required. |

**Recommended: Oracle Cloud free tier** — it's genuinely free with no credit card charges, and the ARM instance has enough resources.

### Minimum requirements
- Ubuntu 22.04 LTS
- 1 vCPU, 1 GB RAM (2 GB preferred)
- 20 GB disk
- Public IPv4 address
- Ports open: **22** (SSH honeypot), **8080** (dashboard), **2222** (Cowrie direct)
- A separate SSH port for YOUR management access (e.g., port 2200)

## 2. Get Your API Keys

### Gemini API Key (free)
1. Go to https://aistudio.google.com/apikey
2. Click "Create API Key"
3. Copy the key — you'll put it in `.env` on the VM

### AbuseIPDB API Key (optional, free)
1. Register at https://www.abuseipdb.com/register
2. Go to API tab → Create Key
3. Free tier: 1,000 checks/day (more than enough)

## 3. Provision the VM

### Oracle Cloud (recommended)
1. Sign up at https://cloud.oracle.com (free tier, no charges)
2. Create a VM instance:
   - Image: Ubuntu 22.04 (Canonical)
   - Shape: VM.Standard.A1.Flex, 1 OCPU, 6 GB RAM
   - Add your SSH public key
3. Note the public IP address

### Firewall / Security List
Open these ports in your cloud provider's firewall:

```
Port 22    → TCP → 0.0.0.0/0   (honeypot SSH — will redirect to Cowrie)
Port 2200  → TCP → YOUR_IP/32  (management SSH — restrict to your IP!)
Port 2222  → TCP → 0.0.0.0/0   (Cowrie direct — optional)
Port 8080  → TCP → YOUR_IP/32  (dashboard — restrict to your IP!)
```

**IMPORTANT**: Before running setup.sh, change your real SSH to port 2200:
```bash
# On the VM, BEFORE deploying:
sudo sed -i 's/^#Port 22/Port 2200/' /etc/ssh/sshd_config
sudo sed -i 's/^Port 22/Port 2200/' /etc/ssh/sshd_config
echo "Port 2200" | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart sshd

# Verify you can still connect on port 2200 before proceeding!
ssh -p 2200 ubuntu@YOUR_VM_IP
```

## 4. Deploy

### First-time deployment (from your Windows machine)

```bash
# 1. Clone the repo on your local machine (if not already)
# 2. From the project directory, deploy to the VM:
bash scripts/deploy.sh ubuntu@YOUR_VM_IP --first-run
```

This will:
- rsync all project files to `/opt/adaptive-honeypot/` on the VM
- Run `setup.sh` (installs Cowrie, Python, Redis, iptables rules)
- Install project dependencies
- Apply the Cowrie integration hook
- Start the dashboard service

### 3. Configure API keys on the VM

```bash
ssh -p 2200 ubuntu@YOUR_VM_IP
sudo nano /opt/adaptive-honeypot/.env
```

Set these values:
```
GEMINI_API_KEY=your-actual-gemini-key
ABUSEIPDB_API_KEY=your-actual-abuseipdb-key   # optional
```

Then restart:
```bash
sudo systemctl restart cowrie
sudo systemctl restart honeypot-dashboard
```

### Subsequent deployments (code updates)

```bash
bash scripts/deploy.sh ubuntu@YOUR_VM_IP
```

No `--first-run` needed — it just syncs code and restarts services.

## 5. Verify It's Working

### Test the honeypot SSH
```bash
# From your local machine — connect AS IF you're an attacker
ssh testuser@YOUR_VM_IP
# (password: anything — Cowrie accepts all after a few tries)

# Try some commands:
whoami
ls /
cat /etc/passwd
uname -a
```

### Check the dashboard
Open in browser: `http://YOUR_VM_IP:8080`

### Check logs
```bash
ssh -p 2200 ubuntu@YOUR_VM_IP

# Cowrie logs
sudo journalctl -u cowrie -f

# Dashboard logs
sudo journalctl -u honeypot-dashboard -f

# Honeypot session logs
ls -la /opt/adaptive-honeypot/event_logging/logs/
```

## 6. Run the Demo (optional)

To demonstrate the system to your panel:

```bash
ssh -p 2200 ubuntu@YOUR_VM_IP

cd /opt/adaptive-honeypot
source .venv/bin/activate

# Terminal 1: Dashboard should already be running on port 8080
# Terminal 2: Run the demo
python scripts/demo_session.py
```

Open `http://YOUR_VM_IP:8080` in the browser while the demo runs.

## 7. Collect Real Data

Once deployed, the honeypot will automatically:
- Accept SSH connections from real attackers (bots scan for open SSH constantly)
- Log all commands to `event_logging/logs/`
- Score each session's threat level
- Switch personas when thresholds are crossed

Typical timeline:
- **Within hours**: first bot connections (automated scanners)
- **Within 1-2 days**: enough sessions for meaningful data
- **1-2 weeks**: solid dataset for evaluation metrics

## 8. Run Evaluation (after collecting data)

```bash
ssh -p 2200 ubuntu@YOUR_VM_IP
cd /opt/adaptive-honeypot
source .venv/bin/activate

python scripts/run_evaluation.py
```

This generates the three evaluation metrics:
1. Fingerprint Resistance Score (our system vs vanilla Cowrie)
2. FakeFS Consistency Score
3. Command Depth Progression

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Can't SSH to VM anymore | You forgot to move real SSH to port 2200 first! Use cloud console to fix. |
| Cowrie not starting | `sudo journalctl -u cowrie -n 50` — check for Python errors |
| Dashboard not loading | `sudo journalctl -u honeypot-dashboard -n 50` — check port conflicts |
| LLM returns "command not found" for everything | Check `GEMINI_API_KEY` is set in `.env` and restart Cowrie |
| No attacker sessions after 24h | Verify port 22 is open in cloud firewall, check `sudo iptables -t nat -L` |
| High LLM latency (>3s) | Normal for complex commands. Fast-path handles 80% of commands instantly. |
