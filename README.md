# Honeypot Atlas — Cyber Threat Observatory (3-tier edition)

A SOC-style dashboard for **simulated** honeypot telemetry, split into three independent tiers:

```
 Browser ──HTTP :80──▶  WEB TIER            APPLICATION TIER           DATA TIER
                        Nginx          ──▶  Node.js / Express    ──▶   PostgreSQL
                        static files        REST API, auth, rules      tables, indexes
                        + /api proxy        engine, simulator          (schema.sql)
                        (public, :80)       (127.0.0.1:3000)           (127.0.0.1:5432)
```

| Tier | Folder | Technology | Listens on | Reachable from |
|---|---|---|---|---|
| Presentation / web | `frontend/` + `deploy/nginx/` | HTML/CSS/vanilla JS served by Nginx | `:80` | your IP only (security group) |
| Application | `backend/` | Node.js ≥ 20.6, Express 5, `pg` | `127.0.0.1:3000` | Nginx only |
| Data | `database/` | PostgreSQL 14+ | `127.0.0.1:5432` | the API only |

> **Safety: everything is simulated.** The simulator only fabricates records with reserved documentation addresses
> (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). The app opens no honeypot listeners, scans nothing and
> contacts no external systems. "Deploy decoy" registers a simulated decoy record only. Real-sensor intake exists but is **off**
> (`INGEST_ENABLED=false`).

## Project structure

```
honeypot-atlas-3tier/
├── frontend/                  TIER 1: static site (no build step)
│   ├── index.html
│   ├── css/  atlas.css (approved design), app.css
│   └── js/   main.js, api.js, ui.js, charts.js, pages/*.js
├── backend/                   TIER 2: API
│   ├── package.json  .env.example
│   ├── src/
│   │   ├── index.js           startup, first-run seeding, retention job
│   │   ├── app.js             Express app, /api/health, route mounting, SSE
│   │   ├── config.js  db.js (pg pool + transactions)  auth.js  util.js  catalog.js
│   │   ├── routes/            events, alerts, decoys, rules, dashboard, admin, ingest
│   │   └── services/          engine.js (event→rules→alerts), simulator.js, seed.js, notify.js
│   ├── scripts/               migrate.js, seed.js, e2e.mjs (optional browser test)
│   └── tests/                 33 tests (API, engine, three-tier behaviour) on real PostgreSQL
├── database/                  TIER 3: schema as plain SQL
│   ├── 00_create_role_and_database.sql
│   └── schema.sql
└── deploy/
    ├── nginx/atlas.conf       web-tier config (static + reverse proxy)
    └── systemd/atlas-api.service
```

No Dockerfiles are included on purpose: see "Practice: containerize it yourself" below.

---

## Demo: run the three tiers by hand on Ubuntu (EC2)

Assumes the project is in `~/honeypot-atlas-3tier` and you use the `ubuntu` user.

### 0. Free the ports used by the old single-container version
```bash
cd ~/honey-pot && docker compose down        # add -v to also delete its old data volume
```

### 1. Install the software
```bash
sudo apt update
sudo apt install -y postgresql nginx curl
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
node -v && psql --version && nginx -v
```

### 2. DATA TIER: PostgreSQL
```bash
cd ~/honeypot-atlas-3tier
# create the application role + empty database (pick your own password)
sudo -u postgres psql -v pw="'Choose-A-Strong-Password'" -f database/00_create_role_and_database.sql
# create the tables as that role
PGPASSWORD='Choose-A-Strong-Password' psql -h 127.0.0.1 -U atlas -d atlas -f database/schema.sql
# verify
PGPASSWORD='Choose-A-Strong-Password' psql -h 127.0.0.1 -U atlas -d atlas -c '\dt'
sudo ss -tlnp | grep 5432            # should show 127.0.0.1:5432 only (PostgreSQL is not public)
```

### 3. APPLICATION TIER: the API
```bash
cd ~/honeypot-atlas-3tier/backend
npm ci --omit=dev
cp .env.example .env
nano .env        # set DATABASE_URL (same password as above) and SEED_PASSWORD (initial password of the 3 demo users)
node --env-file=.env src/index.js
```
On first start it seeds 30 days of simulated history (about 30-60 s) and prints the one-time sensor API key.
Leave it running, open a **second SSH session**, and check it:
```bash
curl -s localhost:3000/api/health      # {"status":"ok","api":"up","database":"up",...}
```
To keep it running after you log out, install it as a service instead of the foreground command (stop the foreground one with Ctrl+C first):
```bash
sudo useradd --system --home /opt/honeypot-atlas --shell /usr/sbin/nologin atlas
sudo mkdir -p /opt/honeypot-atlas /etc/atlas
sudo cp -r ~/honeypot-atlas-3tier/backend ~/honeypot-atlas-3tier/database /opt/honeypot-atlas/
sudo cp ~/honeypot-atlas-3tier/backend/.env /etc/atlas/atlas.env
sudo chown -R atlas:atlas /opt/honeypot-atlas && sudo chown root:atlas /etc/atlas/atlas.env && sudo chmod 640 /etc/atlas/atlas.env
sudo cp ~/honeypot-atlas-3tier/deploy/systemd/atlas-api.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now atlas-api
sudo systemctl status atlas-api --no-pager ; journalctl -u atlas-api -n 20 --no-pager
```
The service reads its settings from `/etc/atlas/atlas.env`.

### 4. WEB TIER: Nginx
```bash
sudo mkdir -p /var/www/atlas
sudo cp -r ~/honeypot-atlas-3tier/frontend/. /var/www/atlas/
sudo cp ~/honeypot-atlas-3tier/deploy/nginx/atlas.conf /etc/nginx/sites-available/atlas
sudo ln -sf /etc/nginx/sites-available/atlas /etc/nginx/sites-enabled/atlas
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
curl -s localhost/api/health            # same answer, now through Nginx
curl -sI localhost/ | head -3           # the static frontend
```

### 5. Open it
- **Safest:** SSH tunnel from your own computer: `ssh -i key.pem -L 8080:127.0.0.1:80 ubuntu@<EC2-IP>` then browse `http://localhost:8080`.
- **Or** in the EC2 security group allow inbound **TCP 80 from My IP only**, then browse `http://<EC2-IP>`.
- **Never** open 3000 or 5432: those tiers must stay private.

Sign in as `a.rivera` (admin), `s.kapoor` (analyst) or `m.chen` (viewer) with the `SEED_PASSWORD` you set.
The seed only runs on an empty database, so changing `SEED_PASSWORD` later does not change existing users;
use *Audit & Settings → Edit → Reset password*.

### 6. Show that the tiers are really independent
```bash
sudo ss -tlnp | grep -E ':80 |:3000|:5432'      # only :80 is on 0.0.0.0 ; API and PostgreSQL are loopback-only

sudo systemctl stop postgresql                  # kill the DATA tier
curl -s -w ' [HTTP %{http_code}]\n' localhost/api/health   # 503 {"api":"up","database":"down"}; the page itself still loads
sudo systemctl start postgresql                 # the API reconnects by itself

sudo systemctl stop atlas-api                   # kill the APPLICATION tier
curl -s -o /dev/null -w 'api: %{http_code}\n' localhost/api/health   # 502 from Nginx
curl -s -o /dev/null -w 'static: %{http_code}\n' localhost/          # 200, the web tier is unaffected
sudo systemctl start atlas-api
```

### 7. Day-2 commands
```bash
# update the frontend: copy again, no restart needed
sudo cp -r ~/honeypot-atlas-3tier/frontend/. /var/www/atlas/
# update the API
sudo systemctl restart atlas-api
# look inside the data tier
PGPASSWORD=... psql -h 127.0.0.1 -U atlas -d atlas -c "select status, count(*) from alerts group by 1"
# backup
PGPASSWORD=... pg_dump -h 127.0.0.1 -U atlas atlas > atlas-backup.sql
# wipe and reseed all demo data (destructive); run with the same environment the service uses
cd ~/honeypot-atlas-3tier/backend && node --env-file=.env scripts/seed.js --reset
```

---

## Configuration (backend `.env`)

| Variable | Default | Purpose |
|---|---|---|
| `HOST`, `PORT` | `127.0.0.1`, `3000` | where the API listens (keep loopback with local Nginx) |
| `DATABASE_URL` | *(required)* e.g. `postgres://<user>:<password>@127.0.0.1:5432/<dbname>` | data tier connection |
| `DB_POOL_MAX` | `10` | connection pool size |
| `AUTO_MIGRATE` | `false` | `true` applies `database/schema.sql` at startup (dev convenience) |
| `TRUST_PROXY` | `loopback` | trust Nginx's `X-Forwarded-For` so audit logs/throttling see the real client |
| `SESSION_TTL_HOURS`, `COOKIE_SECURE` | `12`, `false` | sessions; set `COOKIE_SECURE=true` behind HTTPS |
| `SIMULATOR_ENABLED`, `SIMULATOR_INTERVAL_MS` | `true`, `4000` | synthetic traffic generator |
| `INGEST_ENABLED` | `false` | accept real sensor events on `POST /api/ingest` (needs API key; only with authorization and isolation) |
| `DEMO_MODE` | `true` | shows the "DEMO DATA" pill and footer |
| `SEED_ON_EMPTY`, `SEED_DAYS`, `SEED_PASSWORD` | `true`, `30`, *(set it!)* | first-run seeding |
| `FRONTEND_DIR` | *(empty)* | dev only: let the API serve the static files itself |
| `SMTP_URL`, `MAIL_FROM` | empty | optional alert email |

If the database is unreachable or empty the API refuses to start and says exactly what to run.

## Tests
export DB_PASSWORD='<your-password>'
```bash
# needs a PostgreSQL database the role can create schemas in (each test gets its own throw-away schema)
sudo -u postgres createdb -O atlas atlas_test
cd backend && npm install
export PGUSER=atlas
export PGPASSWORD='<your-password>'
export TEST_DATABASE_URL="postgres://127.0.0.1:5432/atlas_test"
npm test      # 33 tests

# optional browser end-to-end check through Nginx (needs Chromium):
npm i --no-save puppeteer
E2E_URL=http://127.0.0.1 E2E_PASSWORD=<SEED_PASSWORD> node scripts/e2e.mjs
```

## Practice: containerize it yourself (hints, no files provided)
- **db**: image `postgres:16`; env `POSTGRES_USER=atlas`, `POSTGRES_PASSWORD`, `POSTGRES_DB=atlas`; mount `database/schema.sql` into `/docker-entrypoint-initdb.d/`; named volume on `/var/lib/postgresql/data`; healthcheck `pg_isready`. No published port.
- **api**: `node:22-alpine`, `npm ci --omit=dev`, run as the `node` user, `CMD ["node","src/index.js"]`; env `DATABASE_URL=postgres://atlas:...@db:5432/atlas`, `HOST=0.0.0.0`, `TRUST_PROXY=true` (or the Docker network CIDR); wait for the db to be healthy; healthcheck `GET /api/health`. No published port.
- **web**: `nginx:alpine`; copy `frontend/` to `/usr/share/nginx/html`; adapt `deploy/nginx/atlas.conf` (`root /usr/share/nginx/html;`, `server api:3000;`); the only published port (`80`).
- **networks**: put `web`+`api` on one network and `api`+`db` on another so Nginx cannot reach the database.

## How it works (short)
Events enter one pipeline (`engine.ingest`): validate → INSERT → evaluate enabled rules over a time window per source IP → record rule hits →
create one alert per rule+decoy per 12 h window (guarded by a PostgreSQL advisory lock so concurrent events cannot duplicate it) →
notification, optional email and auto-block. Dashboards are computed with SQL on request; open pages refresh via server-sent events.
*Detection rate* = share of events whose type is covered by an enabled rule; *Mean time to ack* = average (acknowledged − created).

## Notes and limitations
- Counts shown are computed from the database (about 2k simulated events/day); the numbers in the original static mock were illustrative.
- Email only works if `SMTP_URL` is set (not tested against a real SMTP server). Invited users get a one-time password shown to the admin.
- "Block IP" keeps a blocklist for export to your perimeter tools; it changes no firewall.
- Plain HTTP on port 80 is fine for a lab; for anything else add HTTPS (e.g. `certbot --nginx` with a domain) and set `COOKIE_SECURE=true`.
- The Docker practice section is guidance only; the Node, Nginx and PostgreSQL steps above were run and tested directly.
