# Deployment Guide - Rust WAF

## Prerequisites

- Linux server (Ubuntu 20.04+ recommended)
- Rust 1.70+
- NGINX 1.18+
- Systemd (for service management)

## Installation Steps

### 1. Build the WAF

```bash
# Clone repository
git clone https://github.com/yourusername/waf-rust.git
cd waf-rust

# Build release binary
cargo build --release

# Binary location: target/release/waf-rust
```

### 2. Install Binary

```bash
sudo cp target/release/waf-rust /usr/local/bin/
sudo chmod +x /usr/local/bin/waf-rust
```

### 3. Create Service User

```bash
sudo useradd -r -s /bin/false waf
```

### 4. Setup Configuration

```bash
sudo mkdir -p /etc/waf
sudo cp config.toml /etc/waf/
sudo chown -R waf:waf /etc/waf
```

Edit `/etc/waf/config.toml`:
```toml
[server]
host = "127.0.0.1"
port = 8000

[upstream]
url = "http://127.0.0.1:8090"  # Your backend app
timeout_seconds = 30
```

### 5. Create Systemd Service

Create `/etc/systemd/system/waf.service`:

```ini
[Unit]
Description=Rust Web Application Firewall
After=network.target

[Service]
Type=simple
User=waf
Group=waf
WorkingDirectory=/etc/waf
ExecStart=/usr/local/bin/waf-rust
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=waf-rust

[Install]
WantedBy=multi-user.target
```

### 6. Enable and Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable waf
sudo systemctl start waf
sudo systemctl status waf
```

### 7. Configure NGINX

Edit `/etc/nginx/sites-available/default`:

```nginx
upstream waf_backend {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://waf_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Test and reload:
```bash
sudo nginx -t
sudo systemctl reload nginx
```

## Monitoring

### View Logs
```bash
# Live logs
sudo journalctl -u waf -f

# JSON logs only (blocked requests)
sudo journalctl -u waf -f | grep '"action":"BLOCK"'
```

### Log Forwarding to SIEM

#### Splunk
Configure forwarder in `/etc/systemd/journald.conf`:
```ini
[Journal]
ForwardToSyslog=yes
```

#### ELK Stack
Use Filebeat to ship logs from journald.

## Performance Tuning

### Increase File Descriptors
Edit `/etc/systemd/system/waf.service`:
```ini
[Service]
LimitNOFILE=65536
```

### Multi-core Scaling
Run multiple instances behind NGINX load balancer:
```bash
# Start on ports 8000-8003
for i in {0..3}; do
  sudo systemctl start waf@$i
done
```

## Health Checks

```bash
# Check WAF is listening
curl http://127.0.0.1:8000/

# Verify blocking
curl "http://127.0.0.1:8000/?q=union+select"
# Expected: 403 Forbidden
```

## Troubleshooting

### WAF won't start
```bash
# Check logs
sudo journalctl -u waf -n 50

# Common issues:
# - Port 8000 already in use
# - Config file not found
# - Upstream unreachable
```

### High CPU usage
```bash
# Check rule count
# Too many complex regex can slow inspection
# Consider pre-compiling rules at startup
```

## Security Hardening

1. **Run as non-root**: Already configured via `waf` user
2. **Firewall**: Only allow NGINX to connect to port 8000
   ```bash
   sudo ufw allow from 127.0.0.1 to any port 8000
   ```
3. **Regular Updates**: Keep Rust and dependencies updated
4. **Audit Logs**: Monitor for suspicious patterns

## Rollback Plan

```bash
# Stop WAF
sudo systemctl stop waf

# Revert NGINX to bypass WAF
# Edit nginx config to point directly to backend
sudo nginx -t && sudo systemctl reload nginx
```

## Production Checklist

- [ ] Binary built with `--release` flag
- [ ] Config reviewed and upstream tested
- [ ] Systemd service enabled
- [ ] NGINX configured with SSL
- [ ] Logs forwarding to SIEM
- [ ] Health checks passing
- [ ] Firewall rules applied
- [ ] Backup plan documented
