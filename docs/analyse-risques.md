# Analyse de risques (EBIOS light)

## Perimetre

- API SOCket, frontend, listener, SQLite (tickets), MongoDB (logs), pipeline CI.

## Actifs critiques

- Logs de securite (donnees sensibles)
- Comptes analysts/admin
- Historique incidents/tickets
- Secrets d'authentification (JWT/API key)

## Menaces principales

1. Injection de faux logs
2. Vol de token JWT
3. Fuite de logs sensibles
4. Indisponibilite du service de collecte
5. Modification non autorisee des tickets

## Evaluation synthese

- Risque eleve: fuite de secrets, absence TLS en environnement expose.
- Risque moyen: disponibilite listener/API, erreurs de configuration CORS.
- Risque faible: indisponibilite courte du frontend seul.

## Mesures implementees

- Auth JWT + roles
- API key d'ingestion
- CORS restreint via variable `CORS_ORIGIN`
- Separation SQL/NoSQL
- CI securite (audit dependances + SAST Semgrep)

## Plan de traitement (prochaine iteration)

- Rotation des secrets et stockage coffre-fort
- TLS obligatoire via reverse proxy
- Rate limiting endpoints sensibles
- Journal d'audit des actions analystes/admin
