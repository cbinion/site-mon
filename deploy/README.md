# Deploying site-mon

One container image, run on a schedule by systemd. Nothing listens on a port.

## On the host, once

```bash
sudo mkdir -p /srv/site-mon/data /etc/site-mon

# The container runs as UID 1000, so the data directory must be writable by it.
sudo chown -R 1000:1000 /srv/site-mon/data

# Targets and alert thresholds. No secrets in here.
sudo cp config.example.toml /srv/site-mon/config.toml
sudo $EDITOR /srv/site-mon/config.toml

# The webhook lives here instead, root-only.
printf 'SITE_MON_DISCORD_WEBHOOK=%s\n' 'https://discord.com/api/webhooks/...' \
    | sudo tee /etc/site-mon/secrets.env > /dev/null
sudo chmod 600 /etc/site-mon/secrets.env
```

Leave `webhook_url` out of `config.toml` entirely. The environment variable
takes precedence, and keeping the credential in a root-only file means the
config can stay world-readable.

## Build and install

```bash
docker build -t site-mon:latest .

sudo cp deploy/site-mon-check.service deploy/site-mon-check.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now site-mon-check.timer
```

## Check it

```bash
systemctl list-timers site-mon-check.timer   # when it next fires
sudo systemctl start site-mon-check.service  # run one pass right now
journalctl -u site-mon-check.service -n 50   # what it found
```

## Reading the history

The database is a plain SQLite file at `/srv/site-mon/data/site-mon.db`.

```bash
sudo sqlite3 /srv/site-mon/data/site-mon.db \
    "SELECT hostname, outcome, cert_days_remaining, checked_at
     FROM checks WHERE checked_at = (SELECT MAX(checked_at) FROM checks);"
```

`site-mon serve` exposes the same thing as JSON on `/status`, but it is not
part of this deployment. Run it by hand if you ever want it.
