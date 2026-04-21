# SOCket - Prototype plateforme SOC

Prototype fonctionnel pour centraliser des logs, detecter des evenements suspects, et suivre des tickets d'incident.

## Fonctionnalites

- Ingestion de logs via API (`/logs/ingest`) avec cle API
- Detection de regles simples (brute force, PowerShell suspect)
- Creation automatique incident + ticket
- Authentification JWT (compte admin par defaut)
- Dashboard SOC, liste de logs et tickets
- Listener Python avec mode simule et mode logs Windows reels

## Arborescence

- `backend/`: API Express + SQLite
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

Compte par defaut:
- utilisateur: `admin`
- mot de passe: `admin123!`

## Lancement local sans Docker

### Backend

```bash
cd backend
npm install
copy .env.example .env
npm start
```

### Frontend

Servir `frontend/public` avec un serveur statique (ex: Live Server).

### Listener

```bash
cd listener-agent
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:API_URL="http://localhost:4000/logs/ingest"
$env:INGEST_API_KEY="dev-ingest-key"
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

## Attention

Ce prototype est pedagogique (MVP) et doit etre durci pour la production:
- rotation des secrets
- TLS obligatoire
- journalisation complete
- tests automatises et scans securite
