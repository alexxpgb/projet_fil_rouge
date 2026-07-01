# Modélisation des menaces — STRIDE
## Projet SOCket

**Méthodologie :** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)  
**Date :** 01/07/2026

---

## 1. Composants et flux de données analysés

```
[Analyste]  ──HTTPS──►  [Nginx TLS]  ──HTTP──►  [Backend API]
                                                      │
[Listener]  ──HTTPS──►  [Nginx TLS]  ──HTTP──►  [Backend API]
                                                      │
                                               ┌──────┴──────┐
                                           [SQLite]      [MongoDB]
```

Points d'entrée identifiés :
- `POST /auth/login` — authentification utilisateur
- `POST /logs/ingest` — ingestion de logs machine
- `GET /logs|/incidents|/tickets` — lecture données SOC
- `PATCH /tickets/:id` — modification de tickets
- `GET /audit-logs` — consultation journal d'audit

---

## 2. Matrice STRIDE par composant

### 2.1 Frontend (Nginx)

| Menace | Description | Mesure en place | Résiduel |
|--------|-------------|-----------------|----------|
| **S** Spoofing | Usurpation d'identité via session volée | JWT Bearer token, expiration 12h | Faible |
| **T** Tampering | Modification du JS frontend en transit | TLS (Nginx self-signed) | Faible |
| **R** Repudiation | Nier une action sur l'interface | Audit trail côté serveur | Nul |
| **I** Info Disclosure | Credentials visibles dans le code source | Suppression des valeurs par défaut | Nul |
| **D** DoS | Saturation du serveur Nginx | Rate limiting upstream, restart policy | Moyen |
| **E** Elevation | XSS → vol de token | Helmet CSP, pas de eval JS | Faible |

### 2.2 API Backend (Express)

| Menace | Description | Mesure en place | Résiduel |
|--------|-------------|-----------------|----------|
| **S** Spoofing | Forge de JWT avec secret faible | `REQUIRE_STRONG_SECRETS=true` (24+ chars) | Faible |
| **S** Spoofing | Usurpation clé API ingestion | Clé API 16+ chars, audit sur refus | Faible |
| **T** Tampering | Injection de faux logs | Validation Zod stricte, clé API requise | Faible |
| **T** Tampering | Modification ticket par analyste non habilité | RBAC (rôles admin/analyst), JWT vérifié | Nul |
| **R** Repudiation | Analyste nie avoir modifié un ticket | `audit_logs` : action + acteur + timestamp | Nul |
| **I** Info Disclosure | Fuite de logs via endpoint non protégé | Auth JWT requise sur tous les GET | Nul |
| **I** Info Disclosure | Erreurs serveur exposant le stack trace | Catch générique, messages neutres | Faible |
| **D** DoS | Brute force `/auth/login` | Rate limit 10/15min + lock compte 5 échecs | Faible |
| **D** DoS | Flood `/logs/ingest` | Rate limit 300/min | Faible |
| **D** DoS | Payload surdimensionné | `express.json({ limit: "1mb" })` | Nul |
| **E** Elevation | Analyste accède aux audit-logs (admin only) | RBAC vérifié : `auth(["admin"])` | Nul |
| **E** Elevation | JWT forgé avec rôle admin | Signature HMAC-SHA256, secret fort | Faible |

### 2.3 Base de données SQLite

| Menace | Description | Mesure en place | Résiduel |
|--------|-------------|-----------------|----------|
| **S** Spoofing | Accès direct au fichier .db | Fichier dans volume Docker, non exposé | Faible |
| **T** Tampering | Modification directe des audit_logs | Pas d'UPDATE/DELETE exposé sur audit_logs | Faible |
| **R** Repudiation | — | Audit_logs append-only par design | Nul |
| **I** Info Disclosure | Lecture du fichier socket.db hors conteneur | Volume monté `/app/data`, accès restreint OS | Faible |
| **D** DoS | Corruption du fichier SQLite | WAL mode, sauvegardes quotidiennes | Moyen |
| **E** Elevation | — | N/A (pas d'accès réseau direct) | Nul |

### 2.4 Base de données MongoDB

| Menace | Description | Mesure en place | Résiduel |
|--------|-------------|-----------------|----------|
| **S** Spoofing | Connexion sans authentification | Auth MongoDB activée (`--auth`) | Nul |
| **T** Tampering | Injection NoSQL via payload | Validation Zod avant insertion, pas de `$where` | Nul |
| **I** Info Disclosure | MongoDB exposé sur réseau hôte | Port non exposé, réseau Docker interne | Nul |
| **D** DoS | Insertion massive de logs | Rate limit ingestion 300/min | Faible |
| **E** Elevation | — | N/A | Nul |

### 2.5 Listener Agent (Python)

| Menace | Description | Mesure en place | Résiduel |
|--------|-------------|-----------------|----------|
| **S** Spoofing | Usurpation du listener (faux agent) | Clé API unique par déploiement | Faible |
| **T** Tampering | Modification des logs avant envoi | TLS entre listener et Nginx | Faible |
| **I** Info Disclosure | Clé API dans variable d'environnement | Pas dans le code source, `.env` gitignored | Faible |
| **D** DoS | Listener crashe, arrêt de la collecte | Boucle try/except, redémarrage automatique | Moyen |

### 2.6 Pipeline CI/CD

| Menace | Description | Mesure en place | Résiduel |
|--------|-------------|-----------------|----------|
| **T** Tampering | Dépendance compromise (supply chain) | npm audit, pip-audit, SBOM Syft | Faible |
| **T** Tampering | Secret poussé dans le dépôt Git | Gitleaks scan sur tout l'historique | Faible |
| **I** Info Disclosure | Secrets exposés dans les logs CI | Pas de secrets en dur dans le code | Nul |
| **E** Elevation | Semgrep finding ignoré | `continue-on-error` retiré — bloquant | Nul |

---

## 3. Synthèse des risques résiduels

| Niveau | Menaces |
|--------|---------|
| **Nul** | Repudiation (audit trail complet), Elevation sur RBAC, Info Disclosure MongoDB |
| **Faible** | Spoofing JWT, forge de token, XSS, injection NoSQL |
| **Moyen** | DoS par saturation Nginx, perte SQLite sans réplication, arrêt listener |
| **Non traité** | TLS avec CA reconnue (self-signed acceptable en prototype), rotation automatique des secrets |

---

## 4. Correspondance ISO 27001 / RGPD

| Contrôle STRIDE | Annexe ISO 27001 | Article RGPD |
|---|---|---|
| Spoofing → Auth forte | A.9 Contrôle d'accès | Art. 32 (sécurité du traitement) |
| Tampering → Intégrité logs | A.12 Opérations de sécurité | Art. 5.1.f (intégrité) |
| Repudiation → Audit trail | A.12.4 Journalisation | Art. 30 (registre des activités) |
| Info Disclosure → TLS | A.10 Cryptographie | Art. 32 (chiffrement) |
| DoS → Rate limiting | A.17 Continuité | Art. 32 (disponibilité) |
| Elevation → RBAC | A.9.2 Gestion des accès | Art. 25 (privacy by design) |
