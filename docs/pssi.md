# Politique de Sécurité des Systèmes d'Information (PSSI)
## Projet SOCket — Plateforme de gestion d'incidents SOC

**Version :** 1.0  
**Date de rédaction :** 01/07/2026  
**Auteur :** Alexandre Petit  
**Statut :** Document de référence — prototype pédagogique B3 Cybersécurité Ynov

---

## 1. Introduction et contexte

### 1.1 Objet du document

La présente Politique de Sécurité des Systèmes d'Information (PSSI) définit les règles, principes et responsabilités encadrant l'utilisation et la protection du système SOCket. Elle constitue le cadre de référence pour toute décision relative à la sécurité de la plateforme.

### 1.2 Présentation du système

SOCket est une plateforme centralisée de gestion d'incidents de cybersécurité destinée aux équipes SOC (Security Operations Center). Elle permet :
- la collecte et la centralisation de logs de sécurité,
- la détection automatique d'événements suspects,
- la création et le suivi de tickets d'incident,
- la traçabilité des actions des analystes via un journal d'audit.

### 1.3 Enjeux de sécurité

SOCket traite des données de sécurité à forte valeur opérationnelle. La compromission de la plateforme aurait pour conséquences :
- la perte d'intégrité des preuves numériques,
- l'impossibilité de détecter ou répondre à des incidents actifs,
- l'exposition des mécanismes de défense à un attaquant.

---

## 2. Périmètre d'application

La présente PSSI s'applique à l'ensemble des composants du système SOCket :

| Composant | Description |
|---|---|
| API backend | Service Express.js, authentification JWT, gestion des incidents |
| Frontend | Interface web d'administration et de visualisation |
| Base SQLite | Stockage utilisateurs, incidents, tickets, audit logs |
| Base MongoDB | Stockage des logs de sécurité ingérés |
| Listener agent | Agent Python de collecte d'événements Windows |
| Infrastructure | Conteneurs Docker, pipeline CI/CD GitHub Actions |

Elle s'applique à toute personne accédant au système : administrateurs, analystes, développeurs.

---

## 3. Principes directeurs

La sécurité de SOCket repose sur les principes suivants, par ordre de priorité :

1. **Disponibilité** — La plateforme doit permettre la détection et la réponse aux incidents en continu.
2. **Intégrité** — Les logs et preuves numériques ne doivent pas pouvoir être altérés.
3. **Confidentialité** — Les données de sécurité sont accessibles uniquement aux personnes habilitées.
4. **Traçabilité** — Toute action sensible doit être journalisée de manière non répudiable.

---

## 4. Gestion des identités et des accès

### 4.1 Rôles et niveaux d'accès (RBAC)

| Rôle | Périmètre d'accès | Restrictions |
|---|---|---|
| **admin** | Accès complet : logs, incidents, tickets, audit-logs, dashboard | Compte unique, accès restreint |
| **analyst** | Logs, incidents, tickets, dashboard | Pas d'accès aux audit-logs ni à la gestion des comptes |
| **listener** | Ingestion de logs via clé API uniquement | Aucun accès à l'interface |

### 4.2 Règles d'authentification

- Authentification par **nom d'utilisateur + mot de passe** (minimum 8 caractères, maximum 200)
- Mot de passe stocké sous forme de **hash bcrypt** avec coût 12
- Émission d'un **token JWT signé** (HS256) valide **12 heures**
- Le JWT_SECRET doit comporter **24 caractères minimum** — vérifié au démarrage
- **Verrouillage temporaire** du compte après 5 échecs de connexion consécutifs (15 minutes)

### 4.3 Authentification de la collecte de logs

- L'ingestion de logs est protégée par une **clé API** (`x-api-key`)
- La clé API doit comporter **16 caractères minimum**
- Toute tentative d'ingestion avec une clé invalide est journalisée dans l'audit trail

### 4.4 Gestion des comptes

- Le compte administrateur initial est créé via les variables d'environnement `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD`
- Le mot de passe par défaut doit être changé immédiatement après le premier déploiement
- Les comptes inutilisés doivent être désactivés

---

## 5. Protection de l'infrastructure

### 5.1 Isolation réseau

- Les services backend et MongoDB communiquent sur un **réseau Docker interne** (`backend-net`)
- **MongoDB n'est pas exposé sur l'hôte** — accessible uniquement par le backend en interne
- L'API backend est exposée sur le port 4000, le frontend sur le port 8080

### 5.2 Durcissement des conteneurs

- Les images Docker sont basées sur des variantes **Alpine** (surface minimale)
- Le service backend s'exécute sous un **utilisateur non-root** (`appuser`)
- Les dépendances sont installées via `npm ci` (reproductibilité, pas de résolution à la volée)
- Les conteneurs redémarrent automatiquement (`restart: unless-stopped`)

### 5.3 Sécurité applicative

- **Helmet.js** : en-têtes HTTP de sécurité (CSP, HSTS, X-Frame-Options, etc.)
- **CORS** : origines autorisées configurées par variable d'environnement (`CORS_ORIGIN`)
- **Rate limiting** : 10 tentatives de connexion par 15 minutes, 300 ingestions par minute
- **Validation stricte des payloads** : schémas Zod sur tous les endpoints entrants
- **Limite de taille** des requêtes JSON : 1 Mo

### 5.4 Gestion des secrets

- Les secrets (JWT_SECRET, INGEST_API_KEY, identifiants admin) sont définis dans un fichier `.env`
- Le fichier `.env` est **exclu du contrôle de version** (`.gitignore`)
- Le `docker-compose.yml` ne contient aucun secret en clair — il référence l'`env_file`
- En production, les secrets doivent être gérés par un coffre-fort (HashiCorp Vault, AWS Secrets Manager, ou équivalent)

---

## 6. Journalisation et traçabilité

### 6.1 Journal d'audit (audit_logs)

Toutes les actions sensibles sont enregistrées de manière automatique et non modifiable :

| Action journalisée | Déclencheur |
|---|---|
| `auth_login_success` | Connexion réussie |
| `auth_login_failed` | Échec de connexion |
| `auth_login_blocked_locked` | Tentative sur compte verrouillé |
| `log_ingest_denied` | Ingestion refusée (mauvaise clé API) |
| `incident_auto_created` | Création automatique d'incident par détection |
| `ticket_updated` | Modification de statut ou d'assignation d'un ticket |

### 6.2 Conservation

- Les audit logs sont stockés en base SQLite avec horodatage ISO 8601
- La base SQLite est sauvegardée quotidiennement (cf. PCA/PRA)
- L'accès aux audit logs est **réservé au rôle admin**

---

## 7. Gestion des incidents de sécurité

### 7.1 Détection automatique

SOCket détecte automatiquement les événements suivants :
- **Suspicion de brute force** : message contenant `failed login` ou `brute force`
- **Exécution suspecte** : message contenant `powershell -enc` ou `mimikatz`

À chaque détection, un incident et un ticket sont créés automatiquement.

### 7.2 Processus de réponse

1. **Détection** : alerte automatique ou signalement analyste
2. **Qualification** : évaluation de la sévérité (info / warning / high / critical)
3. **Assignation** : ticket assigné à un analyste via PATCH `/tickets/:id`
4. **Investigation** : consultation des logs corrélés, audit trail, raw events
5. **Remédiation** : actions correctives documentées dans le ticket
6. **Clôture** : passage du ticket en statut `closed` + post-mortem si critique

---

## 8. Continuité d'activité

| Paramètre | Valeur cible |
|---|---|
| RPO (perte de données maximale tolérée) | 15 minutes (MongoDB) |
| RTO (délai de remise en ligne) | 60 minutes |

Les sauvegardes et la procédure de reprise sont détaillées dans `docs/pca-pra.md`.

---

## 9. Cycle de vie de la sécurité

### 9.1 Pipeline CI/CD sécurisé

À chaque push sur la branche `main`, le pipeline GitHub Actions exécute :
- `npm audit` (niveau modéré) sur le backend
- `pip-audit` sur le listener Python
- Tests d'intégration sécurité (`npm run test:security`)
- Analyse statique SAST (Semgrep, ruleset `p/security-audit`) — **bloquant**
- Scan de l'image Docker (Trivy, sévérité CRITICAL/HIGH) — **bloquant**

### 9.2 Mise à jour des dépendances

- Les dépendances npm et Python sont auditées à chaque cycle CI
- Toute vulnérabilité de niveau modéré ou supérieur bloque le déploiement

### 9.3 Revue de sécurité

- Un audit de sécurité (tests d'intrusion + revue de code) doit être réalisé avant chaque mise en production
- Les findings sont documentés dans `docs/pentest-audit.md` avec état avant/après

---

## 10. Responsabilités

| Rôle | Responsabilité |
|---|---|
| Développeur | Respect des règles de code sécurisé, pas de secrets en clair, mise à jour des dépendances |
| Administrateur système | Gestion des secrets, sauvegardes, surveillance de l'infrastructure |
| Analyste SOC | Qualification et traitement des incidents dans les délais définis |
| Responsable du projet | Validation de la PSSI, arbitrage en cas d'incident majeur |

---

## 11. Conformité réglementaire et normative

### 11.1 RGPD — Mapping article par article

SOCket traite des données à caractère personnel (adresses IP, identifiants utilisateurs, horodatages d'actions). Le tableau ci-dessous détaille la conformité article par article.

| Article RGPD | Exigence | Mesure SOCket |
|---|---|---|
| **Art. 5.1.f** — Intégrité et confidentialité | Traiter les données de façon à garantir sécurité, intégrité et confidentialité | Hash SHA-256 par log, chiffrement transit TLS 1.3, RBAC strict |
| **Art. 25** — Privacy by design / by default | Intégrer la protection des données dès la conception | Validation Zod stricte, principe du moindre privilège, accès audit-logs admin uniquement |
| **Art. 30** — Registre des activités de traitement | Tenir un registre des traitements | Audit trail non modifiable (SQLite audit_logs), horodatage ISO 8601 de chaque action |
| **Art. 32** — Sécurité du traitement | Mettre en place des mesures techniques et organisationnelles appropriées | bcrypt coût 12, TLS 1.3, verrouillage de compte, rate limiting, pipeline CI bloquant |
| **Art. 33** — Notification de violation | Notifier la CNIL dans les 72h en cas de violation de données | Webhook sur incident critique, audit log `log_integrity_violation`, procédure en §7 |

> **Donnée sensible identifiée :** Les adresses IP source des logs constituent des données personnelles au sens du RGPD (Recital 30). Elles sont stockées uniquement le temps nécessaire à l'investigation — politique de rétention à définir en production (recommandation : 12 mois).

### 11.2 ISO 27001 — Contrôles Annex A applicables

| Contrôle ISO 27001 | Domaine | Mise en œuvre SOCket |
|---|---|---|
| **A.9.1.1** — Politique de contrôle d'accès | Gestion des accès | PSSI présente, RBAC admin/analyst documenté |
| **A.9.2.3** — Gestion des droits d'accès privilégiés | Accès privilégiés | Compte admin unique, bootstrap sécurisé |
| **A.9.4.2** — Procédures de connexion sécurisées | Authentification | JWT HS256, bcrypt, verrouillage 5 tentatives |
| **A.10.1.1** — Politique d'utilisation des mesures crypto | Cryptographie | bcrypt coût 12, TLS 1.3, SHA-256 sur les preuves |
| **A.12.4.1** — Journalisation des événements | Journalisation | Audit trail complet, non modifiable |
| **A.12.6.1** — Gestion des vulnérabilités | Vulnérabilités | npm audit, pip-audit, Trivy, Semgrep en CI |
| **A.14.2.3** — Revue technique des applications | Tests | Tests sécurité en CI, pentest documenté |
| **A.16.1.2** — Signalement des incidents de sécurité | Incidents | Webhook critique, procédure escalade |

### 11.3 Procédure de dérogation à la PSSI

Toute dérogation aux règles définies dans cette PSSI doit suivre la procédure suivante :

| Étape | Acteur | Action | Traçabilité |
|---|---|---|---|
| **1. Demande** | Analyste ou développeur | Soumettre une demande écrite avec justification métier et durée souhaitée | Email / ticket |
| **2. Évaluation** | Admin SOC | Évaluer le risque résiduel de la dérogation | — |
| **3. Validation** | Admin SOC | Valider avec durée maximale (jamais permanente) | audit_log `policy_derogation_granted` |
| **4. Application** | Demandeur | Appliquer la dérogation dans le périmètre validé | — |
| **5. Clôture** | Admin SOC | Vérifier la fin de la dérogation à échéance | audit_log `policy_derogation_closed` |

**Règles applicables aux dérogations :**
- Durée maximale : 30 jours (renouvelable une fois sur validation admin)
- Une dérogation permanente est interdite — elle doit conduire à une révision de la PSSI
- Toute dérogation est documentée dans l'audit trail avec l'identité du demandeur, du valideur et la durée

---

## 12. Limites et évolutions (prototype pédagogique)

Les points suivants sont identifiés comme risques résiduels acceptés dans le cadre pédagogique actuel, mais **obligatoires avant toute mise en production** :

| Point | Action requise |
|---|---|
| Absence de TLS | Mettre en place un reverse proxy (Nginx/Traefik) avec certificat Let's Encrypt |
| SQLite non répliqué | Migrer vers PostgreSQL avec réplication |
| Pas de rotation des secrets | Intégrer un gestionnaire de secrets (Vault) |
| Authentification MFA absente | Ajouter TOTP sur le compte admin |
| Logs MongoDB sans authentification | Activer l'authentification MongoDB (`--auth`) |
