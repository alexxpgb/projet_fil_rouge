# Forensics Playbook — SOCket
## Runbook SOC : procédures de réponse aux incidents

**Version :** 1.0 | **Date :** 01/07/2026 | **Auteur :** Alexandre Petit

---

## Comment utiliser ce playbook

Chaque procédure suit la structure : **Trigger → Triage → Collecte → Analyse → Décision → Clôture**.  
Les commandes `curl` s'exécutent avec un token admin valide stocké dans `$TOKEN`.

---

## Playbook 1 — Suspicion de Brute Force

### Trigger
- SOCket crée automatiquement un incident "Suspicion brute force sur \<host\>" (sévérité: high)
- OU : ticket créé depuis la règle de détection ID 1 ou 2

### Triage (< 5 minutes)
```bash
# 1. Confirmer l'incident
curl -H "Authorization: Bearer $TOKEN" http://localhost:4000/incidents | jq '.[] | select(.severity=="high")'

# 2. Récupérer les logs du host concerné (ex: 10.0.0.42)
curl -H "Authorization: Bearer $TOKEN" "http://localhost:4000/logs?host=10.0.0.42&limit=50" | jq '.[] | {timestamp, message, severity}'

# 3. Compter les tentatives dans la fenêtre temporelle
# Analyser la fréquence : si > 3 par seconde → outil automatisé confirmé
```

### Collecte des preuves
```bash
# 4. Vérifier l'intégrité de chaque log avant usage comme preuve
for LOG_ID in $(curl -sH "Authorization: Bearer $TOKEN" "http://localhost:4000/logs?host=10.0.0.42" | jq -r '.[].id'); do
  curl -sH "Authorization: Bearer $TOKEN" "http://localhost:4000/logs/$LOG_ID/verify" | jq '{id: .log_id, ok: .match}'
done

# 5. Exporter l'audit trail
curl -H "Authorization: Bearer $TOKEN" "http://localhost:4000/audit-logs?limit=100" > audit_trail_$(date +%Y%m%d_%H%M%S).json
```

### Analyse
| Critère | Indicateur brute force | Indicateur accès légitime |
|---|---|---|
| Fréquence | > 1 tentative/seconde | < 1/minute |
| Heures | Hors heures ouvrées | Horaires habituels |
| IP source | Inconnue / externe | IP interne connue |
| User-agent | Absent / outil | Navigateur normal |
| Résultat final | Succès après nombreux échecs | Succès direct |

### Décision
- **Brute force confirmé** → Isoler le host source (action hors SOCket), réinitialiser les credentials du host cible, escalader si succès détecté
- **Faux positif** → Documenter dans le ticket, fermer avec note d'explication, affiner la règle de détection

### Clôture
```bash
# Mettre à jour le ticket avec la conclusion
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"status":"closed","assignee_id":1}' \
  http://localhost:4000/tickets/<ID>
```

---

## Playbook 2 — Exécution Suspecte (PowerShell / Mimikatz)

### Trigger
- SOCket crée un incident "Execution suspecte sur \<host\>" (sévérité: **critical**)
- Webhook déclenché → notification immédiate

### Triage (< 2 minutes — incident critique)
```bash
# 1. Confirmer et récupérer le log source
curl -H "Authorization: Bearer $TOKEN" http://localhost:4000/incidents | \
  jq '.[] | select(.severity=="critical") | {id, title, created_at, detected_from_log_id}'

# 2. Consulter le log brut (champ raw = log Windows complet)
curl -H "Authorization: Bearer $TOKEN" "http://localhost:4000/logs?severity=critical&limit=5" | \
  jq '.[0] | {message, raw, host, timestamp}'
```

### Collecte des preuves
```bash
# 3. Capturer l'état immédiat du système via le listener
# (si le host est accessible)
# Vérifier l'intégrité du log critique
curl -H "Authorization: Bearer $TOKEN" "http://localhost:4000/logs/<LOG_ID>/verify"
# → {"ok":true,"match":true} — preuve non altérée ✓
```

### Analyse
- Décoder le payload PowerShell Base64 si disponible dans `raw`
- Rechercher la corrélation avec des activités de brute force précédentes sur le même host
- Identifier si le compte utilisé dans la commande est compromis

### Décision
- **Toujours escalader vers l'admin** pour incident critical
- Isoler immédiatement le host du réseau
- Préserver l'image disque si possible (hors scope SOCket — procédure forensique système)
- Notifier le RSSI

### Clôture
- Post-mortem obligatoire dans les 24h
- Vérifier et mettre à jour les règles de détection si le vecteur est nouveau

---

## Playbook 3 — Suspicion d'Exfiltration de Données

### Trigger
- Volume de logs sortants anormalement élevé depuis un host
- Ou signalement manuel d'un analyste

### Triage
```bash
# Vérifier les métriques de sécurité globales
curl -H "Authorization: Bearer $TOKEN" http://localhost:4000/metrics/security | jq .

# Chercher les logs d'un host avec volume élevé
curl -H "Authorization: Bearer $TOKEN" "http://localhost:4000/logs?host=<HOST>&limit=500" | \
  jq 'length'
```

### Collecte
```bash
# Analyser la distribution temporelle des logs
curl -H "Authorization: Bearer $TOKEN" "http://localhost:4000/logs?host=<HOST>&limit=500" | \
  jq '[.[].timestamp] | sort | group_by(.[0:16]) | map({window: .[0][0:16], count: length})'
```

### Indicateurs d'exfiltration
| Signal | Normal | Suspect |
|---|---|---|
| Volume logs | < 100/h | > 1000/h |
| Fenêtre temporelle | Étalée | Burst soudain |
| Destinations | Internes connues | Externes inconnues |
| Taille transfert | Petits fichiers | Gros volumes |

### Décision
- **Exfiltration confirmée** → Couper les accès réseau, déposer plainte, conserver les preuves avec hash
- **Faux positif** → Documenter, ajuster les seuils de détection

---

## Métriques de performance SOC

| Métrique | Définition | Objectif | Réalisé (scénario) |
|---|---|---|---|
| **MTTD auto** | Temps détection automatique | < 1 sec | ~0 sec |
| **MTTD humain** | Temps prise en charge analyste | < 5 min | 7 min 22 sec |
| **MTTR** | Temps résolution complète | < 4h | 48 min |
| **False Positive Rate** | Faux positifs / total alertes | < 10% | À mesurer sur volume |

> Le MTTD humain de 7 min 22 sec dépasse l'objectif de 5 min — action corrective : ajouter une notification push en sus du webhook.
