# Investigation forensique — Scénario d'incident simulé
## Projet SOCket

**Date du scénario :** 01/07/2026  
**Type d'incident :** Brute force suivi d'une tentative d'exécution suspecte  
**Statut :** Clôturé — actions correctives appliquées

---

## 1. Chronologie de l'incident (Timeline)

| Heure (UTC) | Événement | Source |
|---|---|---|
| 09:14:03 | Premier log `failed login` reçu depuis `10.0.0.42` | MongoDB logs |
| 09:14:05 | 2e tentative échouée — même host | MongoDB logs |
| 09:14:07 | 3e tentative — même host | MongoDB logs |
| 09:14:09 | 4e tentative — même host | MongoDB logs |
| 09:14:11 | 5e tentative → **incident auto-créé** : "Suspicion brute force sur 10.0.0.42" (severity: high) | SQLite incidents |
| 09:14:11 | **Ticket #7 créé** automatiquement et assigné (status: new) | SQLite tickets |
| 09:14:11 | **audit_log** : `incident_auto_created` enregistré | SQLite audit_logs |
| 09:17:44 | Analyste se connecte au dashboard SOC | SQLite audit_logs |
| 09:17:44 | **audit_log** : `auth_login_success` — acteur: analyst1 | SQLite audit_logs |
| 09:18:02 | Analyste consulte les logs filtrés sur host=10.0.0.42 | MongoDB logs |
| 09:19:15 | Nouveau log entrant : `PowerShell -Enc suspicious payload` depuis 10.0.0.42 | MongoDB logs |
| 09:19:15 | **2e incident auto-créé** : "Execution suspecte sur 10.0.0.42" (severity: critical) | SQLite incidents |
| 09:19:15 | **Ticket #8 créé** | SQLite tickets |
| 09:19:15 | **Webhook déclenché** → notification envoyée (incident critique) | server.js |
| 09:21:33 | Analyste met à jour ticket #7 → status: `in_progress`, assignee: analyst1 | SQLite tickets |
| 09:21:33 | **audit_log** : `ticket_updated` — acteur: analyst1, ticket: 7 | SQLite audit_logs |
| 09:28:00 | Analyste escalade ticket #8 vers admin | SQLite tickets |
| 09:35:00 | Admin consulte les audit_logs complets | SQLite audit_logs |
| 09:47:00 | Isolation réseau de 10.0.0.42 décidée (action hors plateforme) | Post-mortem |
| 10:02:00 | Tickets #7 et #8 clôturés, post-mortem ouvert | SQLite tickets |

---

## 2. Preuves collectées

### 2.1 Logs bruts (MongoDB) — extrait

```json
{
  "_id": "668c3a1f2e4b1a0012345678",
  "timestamp": "2026-07-01T09:14:03.000Z",
  "host": "10.0.0.42",
  "event_id": "4625",
  "severity": "warning",
  "source": "Security:Microsoft-Windows-Security-Auditing",
  "message": "Failed login attempt detected for user Administrator",
  "raw": "...",
  "hash": "a3f8c2d1e4b5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1"
}
```

### 2.2 Vérification d'intégrité des preuves

Chaque log stocké dans MongoDB est accompagné d'un champ `hash` (SHA-256 du contenu sérialisé). La vérification s'effectue via l'endpoint dédié :

```bash
# Vérification d'un log spécifique
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:4000/logs/668c3a1f2e4b1a0012345678/verify

# Réponse si non altéré :
{
  "ok": true,
  "log_id": "668c3a1f2e4b1a0012345678",
  "stored_hash": "a3f8c2d1...",
  "computed_hash": "a3f8c2d1...",
  "match": true
}

# Réponse si altéré :
{
  "ok": false,
  "match": false,
  "alert": "INTEGRITY VIOLATION — log may have been tampered"
}
```

### 2.3 Audit trail (SQLite audit_logs)

```
id | actor      | action                  | target_type | target_id | created_at
---+------------+-------------------------+-------------+-----------+---------------------
12 | null       | log_ingest_denied       | log         | null      | 2026-07-01T09:13:59
13 | null       | incident_auto_created   | incident    | 6         | 2026-07-01T09:14:11
14 | analyst1   | auth_login_success      | user        | 2         | 2026-07-01T09:17:44
15 | analyst1   | ticket_updated          | ticket      | 7         | 2026-07-01T09:21:33
16 | null       | incident_auto_created   | incident    | 7         | 2026-07-01T09:19:15
17 | admin      | auth_login_success      | user        | 1         | 2026-07-01T09:35:00
```

### 2.4 Chaîne de custody

| Étape | Responsable | Action | Horodatage |
|---|---|---|---|
| Collecte | Listener agent (automatique) | Ingestion logs depuis 10.0.0.42 | 09:14:03 |
| Détection | SOCket backend (automatique) | Création incident + ticket | 09:14:11 |
| Première intervention | analyst1 | Prise en charge ticket #7 | 09:21:33 |
| Escalade | analyst1 → admin | Ticket #8 escaladé | 09:28:00 |
| Décision | admin | Isolation host 10.0.0.42 | 09:47:00 |
| Clôture | admin | Tickets clos + post-mortem | 10:02:00 |

---

## 3. Analyse de l'incident

### 3.1 Reconstruction de l'attaque

1. **Phase de reconnaissance / brute force** (09:14:03 → 09:14:11)  
   L'hôte `10.0.0.42` a effectué 5 tentatives de connexion échouées en 8 secondes sur le poste surveillé. Le pattern correspond à un outil automatisé (hydra, medusa).

2. **Phase d'exécution** (09:19:15)  
   Après les tentatives brute force, un payload PowerShell encodé en base64 (`-Enc`) a été détecté. Cette technique est typiquement utilisée pour contourner les règles de détection basiques (obfuscation de commande).

3. **Corrélation** : les deux événements proviennent du même host `10.0.0.42` dans un intervalle de 5 minutes, ce qui confirme un attaquant unique ou un outil automatisé.

### 3.2 Indicateurs de compromission (IoC)

| Type | Valeur | Confiance |
|---|---|---|
| IP source | 10.0.0.42 | Haute |
| Event ID Windows | 4625 (logon failure) | Haute |
| Pattern message | `powershell -enc` | Haute |
| Intervalle brute force | < 2 secondes entre tentatives | Haute |

---

## 4. Post-mortem

### 4.1 Cause racine

Accès SSH/RDP avec compte à mot de passe faible exposé sur le réseau interne. L'attaquant a automatisé le brute force puis tenté une exécution via PowerShell.

### 4.2 Chronologie de réponse

| Phase | Délai | Commentaire |
|---|---|---|
| Détection automatique | < 1 seconde | Détection par règle SOCket dès le 5e échec |
| Prise en charge analyste | 7 min 22 sec | MTTD trop long — objectif < 5 min |
| Escalade | 6 min 45 sec | Acceptable |
| Isolation | 28 min | Délai trop long — procédure manuelle hors plateforme |

### 4.3 Actions correctives

| Action | Responsable | Délai |
|---|---|---|
| Réinitialiser les credentials du host 10.0.0.42 | Admin sys | Immédiat |
| Activer MFA sur tous les comptes exposés | Admin sys | J+1 |
| Réduire le seuil de détection brute force à 3 tentatives | Dev | J+2 |
| Automatiser l'isolation réseau depuis la plateforme | Dev | J+7 |
| Former les analystes à la procédure d'escalade | RSSI | J+14 |

### 4.4 Calcul des métriques SOC (MTTD / MTTR)

| Métrique | Formule | Valeur mesurée | Objectif PSSI |
|---|---|---|---|
| **MTTD automatique** | Heure 1er incident créé − Heure 1er log suspect | 09:14:11 − 09:14:03 = **8 secondes** | < 60 secondes |
| **MTTD humain** | Heure prise en charge analyste − Heure 1er incident | 09:21:33 − 09:14:11 = **7 min 22 sec** | < 5 min |
| **MTTR (containment)** | Heure décision d'isolation − Heure 1er incident | 09:47:00 − 09:14:11 = **32 min 49 sec** | < 4h |
| **MTTR (clôture)** | Heure clôture tickets − Heure 1er incident | 10:02:00 − 09:14:11 = **47 min 49 sec** | < 8h |

> **Analyse** : La détection automatique (MTTD = 8 secondes) est excellente. Le MTTD humain dépasse l'objectif de 5 minutes — amélioration prévue via notification push temps réel. Le MTTR reste bien en dessous du seuil critique de 4 heures.

### 4.5 Leçons apprises

- La détection automatique est efficace mais le MTTD humain (prise en charge) est perfectible
- L'isolation réseau doit être intégrée à la plateforme pour réduire le délai de containment
- Les règles de détection doivent être enrichies (UEBA, corrélation temporelle)

---

## 5. Scénario 2 — Exfiltration de données (simulé)

**Date du scénario :** 01/07/2026  
**Type d'incident :** Exfiltration de données via HTTPS sortant anormal  
**Statut :** Clôturé — accès compromis révoqué

### 5.1 Chronologie

| Heure (UTC) | Événement | Source |
|---|---|---|
| 14:02:11 | Log sortant anormal détecté : volume > 200 Mo via HTTPS vers IP externe | MongoDB logs |
| 14:02:11 | Pattern `exfiltration` → **incident auto-créé** : "Exfiltration suspectée depuis SRV-SHARE" (severity: critical) | SQLite incidents |
| 14:02:11 | **Webhook déclenché** → notification admin immédiate | server.js |
| 14:07:33 | Admin se connecte — MTTD humain : **5 min 22 sec** | SQLite audit_logs |
| 14:08:00 | Admin consulte les logs filtrés host=SRV-SHARE sur la dernière heure | MongoDB logs |
| 14:09:45 | Corrélation : 3 logs précédents montrent des accès PowerShell (`Get-ChildItem -Recurse`) | MongoDB logs |
| 14:12:00 | Compte `svc-backup` identifié comme acteur — clé API compromise | Investigation |
| 14:15:00 | Clé API révoquée (`INGEST_API_KEY` régénérée) | Action admin |
| 14:22:00 | Isolation SRV-SHARE décidée | Action hors plateforme |
| 14:55:00 | Tickets clôturés, post-mortem ouvert | SQLite tickets |

### 5.2 Preuves clés

```json
{
  "_id": "668c3a2f2e4b1a0098765432",
  "timestamp": "2026-07-01T14:02:11.000Z",
  "host": "SRV-SHARE",
  "event_id": "5156",
  "severity": "critical",
  "source": "edr",
  "message": "Outbound HTTPS 200MB+ to 185.220.101.47:443 — potential data exfiltration",
  "hash": "b9e1d4c2a3f8c2d1e4b5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
}
```

### 5.3 Vérification d'intégrité des preuves

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:4000/logs/668c3a2f2e4b1a0098765432/verify

# Réponse :
{
  "ok": true,
  "stored_hash": "b9e1d4c2...",
  "computed_hash": "b9e1d4c2...",
  "match": true
}
```

### 5.4 IoCs — Exfiltration

| Type | Valeur | Confiance |
|---|---|---|
| IP de destination | 185.220.101.47 (nœud Tor connu) | Haute |
| Volume anormal | > 200 Mo en moins de 2 minutes | Haute |
| Compte compromis | `svc-backup` (clé API) | Haute |
| Commande précédente | `Get-ChildItem -Recurse` (énumération fichiers) | Haute |
| Port destination | 443 (exfiltration HTTPS pour éviter détection) | Haute |

### 5.5 Chaîne de custody — Exfiltration

| Étape | Responsable | Action | Horodatage |
|---|---|---|---|
| Détection | SOCket backend (automatique) | Incident + ticket créés | 14:02:11 |
| Notification | Webhook (automatique) | Admin notifié | 14:02:11 |
| Investigation | admin | Consultation logs corrélés | 14:07:33 |
| Identification | admin | Compte svc-backup compromis | 14:12:00 |
| Containment | admin | Clé API révoquée | 14:15:00 |
| Isolation | admin | SRV-SHARE isolé | 14:22:00 |
| Clôture | admin | Tickets clos + post-mortem | 14:55:00 |

### 5.6 Métriques SOC — Scénario 2

| Métrique | Valeur | Objectif |
|---|---|---|
| MTTD automatique | ~0 secondes (détection en temps réel) | < 60s |
| MTTD humain | 5 min 22 sec | < 5 min |
| Temps de containment | 12 min 49 sec (révocation clé) | < 30 min |
| MTTR complet | 52 min 49 sec | < 8h |

### 5.7 Actions correctives

| Action | Responsable | Délai |
|---|---|---|
| Analyse forensique du poste SRV-SHARE | Admin sys | Immédiat |
| Audit de toutes les clés API en circulation | Admin | J+1 |
| Rotation systématique des clés API | Dev | J+2 |
| Ajout règle de détection volumétrie réseau | Dev | J+3 |
| Blocage IP Tor en sortie (firewall) | Admin sys | J+1 |
