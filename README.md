# SOCket - Prototype plateforme SOC

Prototype fonctionnel pour centraliser des logs, detecter des evenements suspects, et suivre des tickets d'incident.

## Fonctionnalites

- Ingestion de logs via API (`/logs/ingest`) avec cle API
- Detection de regles simples (brute force, PowerShell suspect)
- Creation automatique incident + ticket
- Authentification JWT avec validation de payload
- Dashboard SOC, liste de logs et tickets
- Listener Python avec mode simule et mode logs Windows reels
- Rate limiting sur login et ingestion de logs
- Journal d'audit securite (`audit_logs`) sur actions sensibles

## Arborescence

- `backend/`: API Express + SQLite + MongoDB (logs)
- `frontend/public/`: interface web statique
- `listener-agent/`: agent de collecte/simulation de logs
- `infra/`: Dockerfiles
- `docs/`: documentation projet

## Lancement rapide avec Docker

```bash
docker compose up --build
```

- Frontend: [http://localhost:8080](http://localhost:8080)
- API: [http://localhost:4000/health](http://localhost:4000/health)
- MongoDB: `mongodb://localhost:27017`

Compte bootstrap:
- utilisateur: defini par `BOOTSTRAP_ADMIN_USERNAME`
- mot de passe: defini par `BOOTSTRAP_ADMIN_PASSWORD`

## Lancement local sans Docker

### Backend

```bash
cd backend
npm install
copy .env.example .env
npm start
```

Variables importantes backend:
- `CORS_ORIGIN` (par defaut `http://localhost:8080`)
- `MONGO_URI`, `MONGO_DB_NAME`, `MONGO_LOG_COLLECTION`
- `REQUIRE_STRONG_SECRETS=true` pour bloquer les secrets trop faibles
- `BOOTSTRAP_ADMIN_USERNAME` et `BOOTSTRAP_ADMIN_PASSWORD` pour creer l'admin au premier demarrage
- `JWT_SECRET` (24+ caracteres recommandes)
- `INGEST_API_KEY` (16+ caracteres recommandes)

### Frontend

Servir `frontend/public` avec un serveur statique (ex: Live Server).

### Listener

```bash
cd listener-agent
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:API_URL="http://localhost:4000/logs/ingest"
$env:INGEST_API_KEY="dev-ingest-key-very-strong"
```

#### Mode simule (evenements de test)

```bash
$env:LISTENER_MODE="simulated"
python listener.py
```

#### Mode reel (logs Windows Event Viewer)

```bash
$env:LISTENER_MODE="windows"
$env:WINDOWS_CHANNELS="Security,System"
python listener.py
```

Notes:
- Le mode `windows` lit les evenements reels de Windows (Security/System).
- Le mode `simulated` envoie des evenements factices pour les demos/tests.

## API principale

- `POST /auth/login`
- `POST /logs/ingest` (header `x-api-key`)
- `GET /logs` (JWT)
- `GET /incidents` (JWT)
- `GET /tickets` (JWT)
- `PATCH /tickets/:id` (JWT)
- `GET /dashboard` (JWT)
- `GET /audit-logs` (JWT admin)

## Hardening implemente

- Validation stricte des payloads avec Zod
- Limitation du trafic sensible (`/auth/login`, `/logs/ingest`)
- CORS restreint via variable d'environnement
- Audit trail des evenements securite en base SQLite
- Verification de robustesse des secrets au demarrage

## CI/CD securite

Pipeline GitHub Actions: `.github/workflows/ci-security.yml`
- `npm audit` backend
- `pip-audit` listener python
- `Semgrep` (SAST) sur le repository

## Documentation projet (note UF)

- `docs/grc.md`
- `docs/analyse-risques.md`
- `docs/pentest-audit.md`
- `docs/pca-pra.md`

## Attention

Ce prototype est pedagogique (MVP) et doit etre durci pour la production:
- rotation des secrets
- TLS obligatoire
- journalisation complete
- tests automatises et scans securite
