# Architecture technique - SOCket

## Composants

- Listener Python sur poste client (collecte/simulation logs)
- API backend Express (ingestion + SOC)
- Base SQLite (logs, incidents, tickets, users)
- Frontend statique (dashboard)

## Flux principal

1. Le listener envoie un log a `POST /logs/ingest` avec `x-api-key`.
2. L'API stocke le log.
3. Une regle de detection peut ouvrir un incident et un ticket.
4. L'analyste se connecte et suit l'etat depuis l'interface.

## Evolutions recommandees

- Remplacer SQLite par PostgreSQL pour production
- Ajouter broker (Kafka/RabbitMQ) pour forte volumetrie
- Ajouter SIEM/ELK pour recherche avancee
