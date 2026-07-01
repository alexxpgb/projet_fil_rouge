# Analyse de risques — SOCket (EBIOS RM simplifié)

## 1. Périmètre

| Composant | Description |
|---|---|
| API backend | Express.js, port 4000, authentification JWT + clé API |
| Frontend | Interface statique Nginx, port 8080 |
| SQLite | Incidents, tickets, utilisateurs, audit logs |
| MongoDB | Logs de sécurité ingérés |
| Listener | Agent Python collectant les événements Windows |
| Pipeline CI | GitHub Actions (audit dépendances, SAST, scan image) |

---

## 2. Actifs critiques

| Actif | Type | Valeur |
|---|---|---|
| Logs de sécurité | Donnée | Haute — preuves numériques |
| Comptes analystes/admin | Identité | Haute — accès plateforme SOC |
| Historique incidents/tickets | Donnée | Haute — traçabilité opérationnelle |
| JWT_SECRET / INGEST_API_KEY | Secret | Critique — compromission = accès total |
| Base SQLite (socket.db) | Donnée | Haute — authentification + audit |
| Base MongoDB (logs) | Donnée | Haute — volumétrie et corrélation |

---

## 3. Sources de menace

| Source | Type | Motivation |
|---|---|---|
| Attaquant externe | Cybercriminelle | Vol de données, déni de service |
| Analyste malveillant | Interne | Effacement de preuves, escalade |
| Défaillance technique | Accidentelle | Perte de disponibilité |
| Erreur de configuration | Accidentelle | Exposition involontaire |

---

## 4. Matrice de risques

> Vraisemblance : 1 (rare) → 4 (quasi-certain)  
> Impact : 1 (négligeable) → 4 (critique)  
> Criticité = Vraisemblance × Impact

| # | Scénario de menace | V | I | Criticité | Traitement |
|---|---|---|---|---|---|
| R1 | Fuite du JWT_SECRET → usurpation d'identité totale | 2 | 4 | **8** | Secrets via env_file, rotation régulière |
| R2 | Injection de faux logs (API key compromise) | 2 | 3 | **6** | Rate limiting, audit log sur refus |
| R3 | Brute force sur `/auth/login` | 3 | 3 | **9** | Rate limit + verrouillage compte après 5 échecs |
| R4 | Accès non autorisé MongoDB (port exposé) | 3 | 4 | **12** | Port retiré du compose, réseau interne Docker |
| R5 | Vol de token JWT actif | 2 | 3 | **6** | Expiration 12h, HTTPS requis en prod |
| R6 | Modification non autorisée d'un ticket | 2 | 3 | **6** | RBAC (admin/analyst), audit trail |
| R7 | Indisponibilité de l'API (crash, surcharge) | 2 | 2 | **4** | restart: unless-stopped, PCA/PRA |
| R8 | Altération des logs (intégrité des preuves) | 1 | 4 | **4** | MongoDB append-only, audit log immutable |
| R9 | Secrets en clair dans docker-compose.yml | 3 | 4 | **12** | Migration vers env_file (corrigé) |
| R10 | Dépendance vulnérable (supply chain) | 2 | 3 | **6** | npm audit + pip-audit en CI |

### Cartographie risques

```
Impact
  4 |        R1      R4,R9
  3 |    R5,R6,R10  R2,R3
  2 |        R7,R8
  1 |
    +------------------------
        1       2       3       4   Vraisemblance

Légende : ≥9 = CRITIQUE | 6-8 = ÉLEVÉ | 4-5 = MOYEN | ≤3 = FAIBLE
```

---

## 5. Mesures de traitement appliquées

| Risque | Mesure implémentée | Statut |
|---|---|---|
| R3 | Rate limiting + verrouillage compte (5 tentatives, 15 min) | ✅ Implémenté |
| R4 | Port MongoDB retiré du compose, réseau interne Docker | ✅ Corrigé |
| R9 | Secrets déplacés vers `backend/.env` via `env_file` | ✅ Corrigé |
| R1 | `REQUIRE_STRONG_SECRETS=true`, vérification au démarrage | ✅ Implémenté |
| R2 | Rate limiting ingestion (300 req/min), audit log sur refus | ✅ Implémenté |
| R6 | JWT RBAC (admin/analyst), validation Zod payload | ✅ Implémenté |
| R10 | npm audit + pip-audit + Semgrep en CI/CD | ✅ Implémenté |
| R5 | Expiration JWT 12h | ✅ Implémenté |
| R7 | restart: unless-stopped, PCA/PRA documenté | ✅ Implémenté |
| R8 | Audit log en append SQLite, timestamps ISO8601 | ✅ Implémenté |

## 6. Risques résiduels acceptés (prototype pédagogique)

- Absence de TLS (HTTPS) — acceptable en environnement local, obligatoire en production
- Pas de rotation automatique des secrets
- SQLite non répliqué (point de défaillance unique pour les tickets)
