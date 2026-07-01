# Durcissement infrastructure — CIS Docker Benchmark
## SOCket — Auto-évaluation

**Référentiel :** CIS Docker Community Edition Benchmark v1.6  
**Date :** 01/07/2026 | **Auteur :** Alexandre Petit

---

## Section 1 — Configuration de l'hôte Docker

| Contrôle CIS | Description | Statut | Preuve |
|---|---|---|---|
| 1.1 | Utilisateur dédié non-root pour Docker | ⚠️ N/A (env pédagogique) | — |
| 1.2 | Version Docker à jour | ✅ Conforme | `docker --version` → 27.x |

---

## Section 2 — Configuration du daemon Docker

| Contrôle CIS | Description | Statut | Preuve |
|---|---|---|---|
| 2.1 | Réseau inter-conteneurs restreint | ✅ Conforme | Réseau `backend-net` interne défini |
| 2.2 | Logging activé | ✅ Conforme | `morgan` + audit_logs applicatif |
| 2.14 | Live restore activé | ⚠️ Non appliqué | Acceptable en prototype |

---

## Section 3 — Configuration des images Docker

| Contrôle CIS | Description | Statut | Preuve |
|---|---|---|---|
| 3.1 | Images depuis sources officielles | ✅ Conforme | `node:20-alpine`, `nginx:stable-alpine`, `mongo:7` |
| 3.2 | Images scannées pour vulnérabilités | ✅ Conforme | Trivy en CI — 0 CRITICAL/HIGH |
| 3.3 | SBOM généré | ✅ Conforme | Syft en CI, artifact `sbom-backend.spdx.json` |
| 3.4 | Images légères (Alpine) | ✅ Conforme | `node:20-alpine` = 180 MB vs 1.1 GB node:20 |

---

## Section 4 — Configuration des conteneurs

| Contrôle CIS | Description | Statut | Preuve |
|---|---|---|---|
| 4.1 | Utilisateur non-root dans le conteneur | ✅ Conforme | `USER appuser` dans Dockerfile.backend |
| 4.2 | Filesystem read-only | ✅ Partiel | `read_only: true` sur frontend ; volume RW sur backend (nécessaire pour SQLite) |
| 4.5 | `--no-new-privileges` | ✅ Conforme | `security_opt: no-new-privileges:true` dans compose |
| 4.6 | Ports exposés limités | ✅ Conforme | Seuls 80/443 exposés via Nginx ; MongoDB et API internes |
| 4.7 | Ressources limitées | ✅ Conforme | `mem_limit` et `cpus` définis par service |
| 4.8 | Capacités Linux supprimées | ⚠️ Partiel | Alpine par défaut — à renforcer avec `cap_drop: ALL` |
| 4.9 | Healthcheck défini | ✅ Conforme | Healthcheck Mongo + restart policies |

---

## Section 5 — Sécurité réseau

| Contrôle CIS | Description | Statut | Preuve |
|---|---|---|---|
| 5.1 | Réseau bridge dédié | ✅ Conforme | `backend-net` isolé du réseau par défaut |
| 5.2 | MongoDB non exposé | ✅ Conforme | Port 27017 absent du mapping `ports:` |
| 5.3 | TLS sur communications exposées | ✅ Conforme | Nginx TLS 1.2/1.3, certificat auto-signé |
| 5.4 | Authentification MongoDB | ✅ Conforme | `MONGO_INITDB_ROOT_USERNAME/PASSWORD` |

---

## Section 6 — Sécurité des secrets

| Contrôle CIS | Description | Statut | Preuve |
|---|---|---|---|
| 6.1 | Secrets hors docker-compose.yml | ✅ Conforme | `env_file: backend/.env`, compose sans secrets |
| 6.2 | .env dans .gitignore | ✅ Conforme | `.env` listé dans `.gitignore` |
| 6.3 | Validation force secrets au boot | ✅ Conforme | `REQUIRE_STRONG_SECRETS=true` |
| 6.4 | Rotation des secrets documentée | ✅ Conforme | Procédure dans `pssi.md` |

---

## Avant / Après — Tableau de synthèse

| Mesure | Avant correction | Après correction |
|---|---|---|
| MongoDB port exposé | `27017:27017` dans compose | Port retiré — interne uniquement |
| MongoDB auth | Aucune | `--auth` avec credentials env |
| Utilisateur conteneur | root | `appuser` non-root |
| Secrets dans compose | En clair | `env_file` |
| Image scannée | Non | Trivy en CI |
| Ressources limitées | Illimitées | `mem_limit` + `cpus` |
| TLS | HTTP pur | Nginx TLS 1.2/1.3 |
| Réseau Docker | Bridge par défaut | `backend-net` dédié |

---

## Commandes de vérification

```bash
# Vérifier l'utilisateur dans le conteneur backend
docker exec socket-backend-1 whoami
# → appuser ✅

# Vérifier que MongoDB n'est pas accessible depuis l'hôte
nc -zv localhost 27017
# → Connection refused ✅

# Vérifier TLS
curl -kI https://localhost | grep -E "HTTP|Strict"
# → HTTP/1.1 301 (redirect HTTP→HTTPS) ✅
# → Strict-Transport-Security: max-age=63072000 ✅

# Vérifier les limites ressources
docker stats --no-stream
# → backend: MEM LIMIT 256MiB, CPU max 50% ✅
```
