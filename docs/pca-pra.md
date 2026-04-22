# PCA / PRA - SOCket

## Objectifs

- Assurer la continuite minimale du suivi incident.
- Restaurer rapidement la plateforme apres incident technique.

## Cibles

- RPO: 15 minutes pour les logs MongoDB
- RTO: 60 minutes pour remise en ligne complete

## Strategie

- Sauvegarde SQLite (`backend/data/socket.db`) quotidienne
- Sauvegarde MongoDB (`mongodump`) toutes les 15 minutes
- Versionning des configurations (Git)

## Procedure PRA (resume)

1. Identifier la cause (panne service, corruption donnees, compromission)
2. Isoler le composant impacte
3. Restaurer SQLite depuis backup valide
4. Restaurer MongoDB depuis dernier dump sain
5. Redemarrer backend + frontend
6. Verifier integrite via `/health`, dashboard et echantillon de tickets
7. Ouvrir incident post-mortem et actions correctives
