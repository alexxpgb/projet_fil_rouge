# GRC - SOCket (base)

## Perimetre

Application SOCket: API, base de donnees, listener client, interface analyste.

## Actifs

- Logs de securite (sensibles)
- Comptes analystes/admin
- Base incidents/tickets
- Serveur API

## Risques majeurs

- Fuite de logs (confidentialite)
- Escalade de privilege sur API
- Indisponibilite de la collecte
- Alteration des preuves (integrite)

## Mesures initiales

- Auth JWT + RBAC
- Cle API pour ingestion
- Sauvegarde reguliere du dossier `backend/data`
- Journalisation des actions critiques (a enrichir)

## KPI proposes

- MTTD (temps moyen de detection)
- MTTR (temps moyen de remediation)
- Taux de tickets clos/semaine
- Nombre d'incidents critiques ouverts
