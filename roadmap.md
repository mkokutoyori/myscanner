# Roadmap - VulnScan Platform

## Vision
> Plateforme open-source d'audit et de scan de vulnérabilités end-to-end, multi-vendor, avec analyse de configuration profonde, pentesting contrôlé, et remédiation automatisée pour entreprises.

## Backlog Priorisé

### Phase 1 - POC & Infrastructure (P0)
- **[R-001]** Discovery Pipeline - masscan/nmap intégration avec normalisation des résultats
  - Owner: DevTeam
  - ETA: 2025-11-24
  - Estimate: 10j/h
  - Status: In Progress

- **[R-002]** Worker System - Architecture Celery avec workers conteneurisés
  - Owner: DevTeam
  - ETA: 2025-11-24
  - Estimate: 8j/h
  - Status: In Progress

- **[R-003]** Vault Integration - Gestion sécurisée des credentials
  - Owner: DevTeam
  - ETA: 2025-11-24
  - Estimate: 5j/h
  - Status: In Progress

- **[R-004]** Database Schema - PostgreSQL models pour assets/scans/findings
  - Owner: DevTeam
  - ETA: 2025-11-24
  - Estimate: 4j/h
  - Status: In Progress

- **[R-005]** Basic UI - React SPA pour visualiser assets et findings
  - Owner: DevTeam
  - ETA: 2025-11-24
  - Estimate: 6j/h
  - Status: In Progress

### Phase 2 - Plugin System (P0)
- **[R-006]** Plugin SDK - Interface Python/Go pour écrire des plugins
  - Owner: DevTeam
  - ETA: 2025-12-08
  - Estimate: 8j/h
  - Status: Pending

- **[R-007]** Linux Plugin - SSH + Lynis/OpenSCAP
  - Owner: DevTeam
  - ETA: 2025-12-08
  - Estimate: 7j/h
  - Status: Pending

- **[R-008]** Plugin Loader - Dynamic loading et sandboxing
  - Owner: DevTeam
  - ETA: 2025-12-08
  - Estimate: 5j/h
  - Status: Pending

### Phase 3 - Approval & Security (P0)
- **[R-009]** Approval Workflow - Gating pour scans intrusifs
  - Owner: DevTeam
  - ETA: 2025-12-15
  - Estimate: 6j/h
  - Status: Pending

- **[R-010]** RBAC System - Role-based access control
  - Owner: DevTeam
  - ETA: 2025-12-15
  - Estimate: 8j/h
  - Status: Pending

- **[R-011]** Audit Logging - Logs immuables de toutes les actions
  - Owner: DevTeam
  - ETA: 2025-12-15
  - Estimate: 4j/h
  - Status: Pending

### Phase 4 - Windows & Active Directory (P1)
- **[R-012]** Windows Plugin - WinRM + enumeration non-destructive
  - Owner: DevTeam
  - ETA: 2026-01-12
  - Estimate: 10j/h
  - Status: Pending

- **[R-013]** AD Enumeration - LDAP/SMB collection, BloodHound compatible
  - Owner: DevTeam
  - ETA: 2026-01-26
  - Estimate: 12j/h
  - Status: Pending

- **[R-014]** AD Security Checks - Kerberoasting, NTLM misconfig detection
  - Owner: DevTeam
  - ETA: 2026-02-09
  - Estimate: 8j/h
  - Status: Pending

### Phase 5 - Network Devices (P1)
- **[R-015]** Network Device Discovery - SNMP/SSH/API fingerprinting
  - Owner: DevTeam
  - ETA: 2026-02-23
  - Estimate: 7j/h
  - Status: Pending

- **[R-016]** Config Collection - Netmiko/Napalm/Nornir intégration
  - Owner: DevTeam
  - ETA: 2026-03-09
  - Estimate: 10j/h
  - Status: Pending

- **[R-017]** Config Analysis - ciscoconfparse + checks CIS
  - Owner: DevTeam
  - ETA: 2026-03-23
  - Estimate: 8j/h
  - Status: Pending

### Phase 6 - Database Support (P1)
- **[R-018]** Database Plugin Framework - Support multi-DB
  - Owner: DevTeam
  - ETA: 2026-04-13
  - Estimate: 6j/h
  - Status: Pending

- **[R-019]** PostgreSQL Plugin - Audit config et permissions
  - Owner: DevTeam
  - ETA: 2026-04-20
  - Estimate: 5j/h
  - Status: Pending

- **[R-020]** Oracle Plugin - cx_Oracle + security checks
  - Owner: DevTeam
  - ETA: 2026-05-04
  - Estimate: 8j/h
  - Status: Pending

- **[R-021]** SQL Server Plugin - pyodbc + permission audit
  - Owner: DevTeam
  - ETA: 2026-05-18
  - Estimate: 7j/h
  - Status: Pending

- **[R-022]** MySQL Plugin - Security checks + weak credentials
  - Owner: DevTeam
  - ETA: 2026-05-25
  - Estimate: 5j/h
  - Status: Pending

- **[R-023]** Progress DB Plugin - ODBC/JDBC connector
  - Owner: DevTeam
  - ETA: 2026-06-08
  - Estimate: 6j/h
  - Status: Pending

### Phase 7 - Pentest Module (P1)
- **[R-024]** PoC Framework - Sandboxed exploit execution
  - Owner: DevTeam
  - ETA: 2026-06-22
  - Estimate: 10j/h
  - Status: Pending

- **[R-025]** Metasploit Integration - Encapsulated MSF RPC
  - Owner: DevTeam
  - ETA: 2026-07-06
  - Estimate: 8j/h
  - Status: Pending

- **[R-026]** CrackMapExec/Impacket - Controlled exploitation
  - Owner: DevTeam
  - ETA: 2026-07-20
  - Estimate: 7j/h
  - Status: Pending

- **[R-027]** Blast Radius Control - Throttling et safety limits
  - Owner: DevTeam
  - ETA: 2026-07-27
  - Estimate: 5j/h
  - Status: Pending

### Phase 8 - Correlation & Intelligence (P2)
- **[R-028]** CVE/NVD Feed Ingestion - Automated updates
  - Owner: DevTeam
  - ETA: 2026-08-10
  - Estimate: 6j/h
  - Status: Pending

- **[R-029]** Neo4j Graph Integration - Attack path visualization
  - Owner: DevTeam
  - ETA: 2026-08-24
  - Estimate: 8j/h
  - Status: Pending

- **[R-030]** Risk Scoring Engine - Custom scoring + CPE mapping
  - Owner: DevTeam
  - ETA: 2026-09-07
  - Estimate: 7j/h
  - Status: Pending

- **[R-031]** Correlation Rules - Multi-step attack detection
  - Owner: DevTeam
  - ETA: 2026-09-21
  - Estimate: 8j/h
  - Status: Pending

### Phase 9 - Reporting & Remediation (P2)
- **[R-032]** Advanced Dashboards - Customizable views
  - Owner: DevTeam
  - ETA: 2026-10-05
  - Estimate: 8j/h
  - Status: Pending

- **[R-033]** PDF/HTML Export - Professional reports
  - Owner: DevTeam
  - ETA: 2026-10-12
  - Estimate: 5j/h
  - Status: Pending

- **[R-034]** Jira Integration - Auto-ticket creation
  - Owner: DevTeam
  - ETA: 2026-10-19
  - Estimate: 4j/h
  - Status: Pending

- **[R-035]** Ansible Playbooks - Automated remediation
  - Owner: DevTeam
  - ETA: 2026-11-02
  - Estimate: 10j/h
  - Status: Pending

- **[R-036]** Nornir Integration - Network device remediation
  - Owner: DevTeam
  - ETA: 2026-11-16
  - Estimate: 6j/h
  - Status: Pending

### Phase 10 - Production Hardening (P1)
- **[R-037]** High Availability - Multi-node deployment
  - Owner: DevTeam
  - ETA: 2026-11-30
  - Estimate: 8j/h
  - Status: Pending

- **[R-038]** Backup & Recovery - Disaster recovery procedures
  - Owner: DevTeam
  - ETA: 2026-12-07
  - Estimate: 5j/h
  - Status: Pending

- **[R-039]** Performance Optimization - Caching, query optimization
  - Owner: DevTeam
  - ETA: 2026-12-21
  - Estimate: 8j/h
  - Status: Pending

- **[R-040]** Air-gapped Deployment - Offline installation support
  - Owner: DevTeam
  - ETA: 2027-01-11
  - Estimate: 6j/h
  - Status: Pending

## Sprints & Jalons

### Sprint 1 - POC Infrastructure (2025-11-10 → 2025-11-24)
**Objectif:** Livrer un POC fonctionnel avec discovery, workers, et UI basique

**Livrables:**
- Architecture monorepo complète (backend/frontend/infra/docs)
- Backend FastAPI avec endpoints REST de base
- Worker Celery + Redis pour orchestration
- Plugin discovery (masscan → nmap) fonctionnel
- PostgreSQL schema pour assets/scans/findings
- Vault intégré pour 1 type de credential
- React UI affichant liste d'assets et findings
- Docker Compose pour environnement local
- CI/CD avec GitHub Actions
- roadmap.md (ce fichier)

**Critères d'acceptation:**
- [ ] `POST /api/scans/discovery` lance un scan masscan → nmap
- [ ] Worker exécute nmap dans container isolé
- [ ] Résultats normalisés stockés dans PostgreSQL (≥10 assets test)
- [ ] UI affiche assets avec ports ouverts et services identifiés
- [ ] Credentials SSH récupérés depuis Vault par worker
- [ ] Tests unitaires ≥60% coverage backend
- [ ] `docker-compose up` démarre toute la stack
- [ ] Documentation README.md avec quickstart

**Risques Sprint 1:**
- Complexité Docker networking → mitigation: utiliser réseau bridge simple
- Performance masscan → mitigation: throttling paramétrable

---

### Sprint 2 - Plugin SDK & Linux Auditing (2025-11-25 → 2025-12-08)
**Objectif:** SDK documenté et premier plugin Linux opérationnel

**Livrables:**
- Plugin SDK Python avec interface standardisée
- Plugin loader dynamique
- Plugin Linux (SSH) avec Lynis et OpenSCAP intégrés
- Normalisation findings au format JSON standard
- Documentation SDK + exemples
- Tests d'intégration plugin

**Critères d'acceptation:**
- [ ] SDK permet création plugin en <200 lignes Python
- [ ] Plugin Linux se connecte en SSH et exécute Lynis
- [ ] Findings Lynis normalisés (severity, CVE si applicable, remediation)
- [ ] Au moins 3 checks OpenSCAP exécutés et parsés
- [ ] Plugin isolé dans container séparé
- [ ] Documentation SDK avec tutoriel "Hello World Plugin"

**Risques Sprint 2:**
- Sandboxing plugins → mitigation: containers rootless + seccomp profiles

---

### Sprint 3 - Security & Approval Workflow (2025-12-09 → 2025-12-22)
**Objectif:** Sécuriser la plateforme et implémenter gating des scans intrusifs

**Livrables:**
- RBAC complet (roles: admin, auditor, operator, viewer)
- Approval workflow pour scans niveau "intrusive"
- Audit logging immuable (PostgreSQL + append-only)
- OAuth2/OIDC authentication
- API rate limiting et quotas
- Blast radius controls (throttling, horaires, blacklists)

**Critères d'acceptation:**
- [ ] User avec role "auditor" ne peut pas lancer scan intrusif
- [ ] Scan marqué "intrusive" nécessite approval d'un admin
- [ ] Toutes actions audit loggées avec timestamp + user + IP
- [ ] Logs audit non modifiables (append-only table)
- [ ] OAuth2 login fonctionnel (Keycloak test)
- [ ] API throttling: max 100 req/min/user

**Risques Sprint 3:**
- Complexité OAuth2 → mitigation: utiliser FastAPI OAuth2 helpers
- Performance logs audit → mitigation: indexation PostgreSQL

---

### Sprint 4 - Windows & Active Directory (2025-12-23 → 2026-01-26)
**Objectif:** Support complet énumération Windows/AD non-destructive

**Livrables:**
- Plugin Windows (WinRM)
- Plugin Active Directory (ldap3, impacket)
- BloodHound data collector compatible
- Checks Kerberoasting, NTLM relay, LDAPS
- Neo4j graph pour relations AD

**Critères d'acceptation:**
- [ ] Connection WinRM avec credentials Vault
- [ ] Enumération AD: users, groups, computers, GPOs
- [ ] Export JSON compatible BloodHound
- [ ] Détection ≥5 misconfigurations AD (e.g., AdminCount, SPN)
- [ ] Graph Neo4j avec chemins privilégiés visualisables

**Risques Sprint 4:**
- Détection par EDR → mitigation: modes furtifs, LDAP read-only queries
- Permissions AD insuffisantes → mitigation: doc des droits requis

---

### Sprint 5 - Network Devices (2026-01-27 → 2026-03-23)
**Objectif:** Collection et analyse configs équipements réseau (Cisco, Juniper, Huawei, Palo Alto)

**Livrables:**
- Discovery SNMP/SSH/API multi-vendor
- Netmiko/Napalm/Nornir intégration
- ciscoconfparse pour parsing configs
- Checks CIS Cisco IOS, Junos
- Detection password plaintext, SNMP community strings

**Critères d'acceptation:**
- [ ] Collecte config via SSH pour ≥4 vendors (Cisco, Juniper, Huawei, Palo)
- [ ] Parsing config et extraction ACLs, interfaces, routes
- [ ] Au moins 10 checks de sécurité CIS implémentés
- [ ] Détection mots de passe en clair dans configs
- [ ] Support NETCONF/RESTCONF pour Juniper/Cisco

**Risques Sprint 5:**
- Diversité syntaxes vendor → mitigation: TextFSM templates
- Timeouts SSH → mitigation: retry logic + paramétrage timeout

---

### Sprint 6 - Database Support (2026-03-24 → 2026-06-08)
**Objectif:** Plugins pour auditer bases de données enterprise

**Livrables:**
- Plugin PostgreSQL (psycopg2)
- Plugin Oracle (cx_Oracle)
- Plugin SQL Server (pyodbc/pymssql)
- Plugin MySQL
- Plugin Progress (ODBC/JDBC)
- Checks permissions, comptes weak, injection vulns (sqlmap intégration)

**Critères d'acceptation:**
- [ ] Connexion authentifiée aux 5 DB types
- [ ] Audit permissions: detection comptes over-privileged
- [ ] Check paramètres sécurité (SSL, encryption at rest)
- [ ] sqlmap wrapper pour tests injection (gated)
- [ ] Findings normalisés avec severity + remediation

**Risques Sprint 6:**
- Licences Oracle client → mitigation: Oracle Instant Client (free)
- Connectivité Progress → mitigation: doc drivers ODBC/JDBC
- Impact scans DB → mitigation: read-only queries, mode non-intrusive par défaut

---

### Sprint 7 - Pentest Module (2026-06-09 → 2026-07-27)
**Objectif:** Framework PoC avec exploitation contrôlée

**Livrables:**
- Sandbox pour exploits (containers éphémères)
- Metasploit RPC encapsulation
- CrackMapExec/impacket wrappers
- Gating strict: approval multi-niveau
- Blast radius controls (limit targets, throttling)
- Evidence collection automatique

**Critères d'acceptation:**
- [ ] Exploit PoC exécuté uniquement après 2 approvals (operator + admin)
- [ ] Container exploit détruit après exécution
- [ ] Logs forensics collectés (PCAP, screenshots, memory dumps)
- [ ] ≥3 modules Metasploit testés (e.g., EternalBlue, BlueKeep)
- [ ] CrackMapExec pour password spraying (contrôlé, max 3 attempts)
- [ ] Dashboard "Pentest" avec status exploits, approvals

**Risques Sprint 7:**
- Légalité exploits → mitigation: disclaimers, approval workflow, audit logs
- Escape sandbox → mitigation: seccomp, AppArmor, network isolation
- Dommages collatéraux → mitigation: mode "dry-run", restoration points

---

### Sprint 8-10 - Correlation, Reporting, Production (2026-07-28 → 2027-01-11)
**Objectif:** Productionisation, reporting avancé, correlation intelligente

**Livrables (résumé):**
- CVE/NVD feeds automatiques
- Neo4j attack paths multi-step
- Risk scoring custom
- Dashboards avancés (Grafana-style)
- Export PDF/HTML professionnels
- Jira/ServiceNow intégration
- Ansible/Nornir playbooks remédiation
- HA deployment
- Backup/restore
- Air-gapped install support
- Performance tuning

**Critères d'acceptation:**
- [ ] Correlation engine détecte chemins d'attaque ≥2 steps
- [ ] CVE feeds mis à jour quotidiennement
- [ ] Reports PDF avec branding custom
- [ ] Auto-création tickets Jira pour findings critiques
- [ ] Playbook Ansible patch ≥1 vulnérabilité automatiquement
- [ ] Déploiement K8s HA (3 replicas API, 5 workers)
- [ ] Installation offline (air-gapped) documentée et testée

---

## Responsables & Ownership

| Module | Owner | Backup |
|--------|-------|--------|
| Backend API | DevTeam | - |
| Workers & Queue | DevTeam | - |
| Plugin SDK | DevTeam | - |
| Frontend UI | DevTeam | - |
| Infra (Docker/K8s) | DevTeam | - |
| Security (Vault, RBAC) | DevTeam | - |
| Documentation | DevTeam | - |

*Note: Équipe initiale unique, à étendre avec ownership spécialisé dès Sprint 4.*

---

## Risques & Mitigations

### 🔴 Risque R1: Exécution non-autorisée de scans intrusifs / exploits
**Impact:** Critique (légal, éthique, dommages)
**Probabilité:** Moyenne (si pas de contrôles)
**Mitigation:**
- Approval workflow obligatoire multi-niveau pour scans "intrusive" et "exploit"
- RBAC strict: seuls admins peuvent approuver
- Audit logs immuables de toutes tentatives
- Blast radius controls: throttling, blacklists, horaires
- Disclaimers légaux + consentement écrit dans UI
- Mode "dry-run" par défaut pour nouveaux plugins

---

### 🟠 Risque R2: Fuite de credentials via Vault
**Impact:** Critique (accès systèmes clients)
**Probabilité:** Faible (si Vault bien configuré)
**Mitigation:**
- Vault en mode HA avec unseal keys distribués
- Credentials jamais loggés (scrubbing automatique)
- Token workers éphémères (TTL 1h)
- Audit Vault accès credentials
- Chiffrement TLS obligatoire API ↔ Vault
- Secret rotation automatique (90j)

---

### 🟠 Risque R3: Détection et blocage par EDR/IDS
**Impact:** Moyen (scans échouent, faux positifs)
**Probabilité:** Élevée (scans authentifiés Windows/AD)
**Mitigation:**
- Modes furtifs: rate limiting, randomisation timing
- LDAP queries read-only (pas SMB Named Pipes suspects)
- User-agent customisable pour HTTP scans
- Documentation des whitelists EDR requises
- Coordination avec équipes SOC clients

---

### 🟠 Risque R4: Performance insuffisante (scans lents, timeouts)
**Impact:** Moyen (UX dégradée, scans incomplets)
**Probabilité:** Moyenne (large networks)
**Mitigation:**
- Scaling horizontal workers (K8s HPA)
- Caching résultats intermédiaires (Redis)
- Masscan pour discovery rapide, nmap pour deep scan
- Timeouts paramétrables par plugin
- Priority queues (critical assets first)

---

### 🟡 Risque R5: Complexité multi-vendor (network devices, DB)
**Impact:** Moyen (effort dev, maintenance)
**Probabilité:** Élevée (diversité équipements)
**Mitigation:**
- Architecture plugin-first, vendor-isolated
- TextFSM templates pour parsing (communauté)
- Tests d'intégration avec émulateurs (GNS3, EVE-NG)
- Documentation vendor-specific claire
- Roadmap progressive: commencer vendors communs (Cisco, Juniper)

---

### 🟡 Risque R6: Licences OSS et dépendances propriétaires
**Impact:** Faible (légal, distribution)
**Probabilité:** Faible (stack OSS)
**Mitigation:**
- Audit licences automatisé (licensecheck, FOSSA)
- Whitelist licences: MIT, Apache 2.0, BSD, GPL (avec attention)
- Drivers propriétaires (Oracle Instant Client) optionnels, docs séparées
- Alternative JDBC/ODBC bridges open-source quand possible

---

### 🟡 Risque R7: Sandboxing escape (plugins/exploits malveillants)
**Impact:** Critique (compromission plateforme)
**Probabilité:** Faible (containers bien configurés)
**Mitigation:**
- Containers rootless (Podman/Docker rootless)
- Seccomp profiles stricts (deny syscalls dangereux)
- AppArmor/SELinux policies
- Network policies K8s (deny egress par défaut)
- Code review plugins avant production
- Signature plugins (GPG) pour marketplace futur

---

### 🟢 Risque R8: Adoption limitée (complexité déploiement)
**Impact:** Moyen (ROI projet)
**Probabilité:** Moyenne (stack complexe)
**Mitigation:**
- Docker Compose one-liner pour POC local
- Helm charts avec defaults sains
- Documentation pas-à-pas (screenshots)
- Tutoriels vidéo
- Support community (Discord/Slack)

---

## Métriques de Succès (KPIs)

### MVP (Sprint 1)
- [ ] 10 assets découverts et affichés dans UI
- [ ] 1 scan nmap complet en <5min (réseau /24)
- [ ] 0 credentials en clair dans logs/DB
- [ ] 60% code coverage tests

### Phase 1-3 (Q4 2025)
- [ ] 3 plugins opérationnels (discovery, Linux, Windows)
- [ ] Approval workflow testé en prod
- [ ] 100 assets audités en environnement test
- [ ] 80% code coverage

### Phase 4-7 (H1 2026)
- [ ] Support 5 vendors réseau + 5 types DB
- [ ] 500 assets audités
- [ ] ≥1000 findings détectés et normalisés
- [ ] 10 playbooks remédiation Ansible

### Production (Q4 2026)
- [ ] Déploiement chez ≥3 clients pilotes
- [ ] 5000 assets sous audit continu
- [ ] 0 incident sécurité plateforme
- [ ] ≥20 plugins communautaires (marketplace)

---

## Historique des Changements

### 2025-11-10 — Initial Roadmap Creation
**Auteur:** DevTeam
**Résumé:** Création roadmap.md initial avec vision, backlog 40 items (R-001 à R-040), sprints 1-10, risques & mitigations. Planning sur 14 mois (Sprint 1: 2025-11-10 → Sprint 10: 2027-01-11). Priorités P0 pour POC/plugin system/security, P1 pour Windows/Network/DB/Pentest, P2 pour correlation/reporting avancé.

**Décisions clés:**
- Stack Python/FastAPI + Celery + PostgreSQL + Vault + React
- Architecture plugin-first pour extensibilité
- Approval workflow obligatoire dès Sprint 3
- Support multi-DB (Oracle, SQL Server, Progress) en Sprint 6
- Neo4j pour graph AD/attack paths en Sprint 8

**Risques identifiés:** 8 risques majeurs documentés (R1-R8) avec mitigations

**Liens issues:** N/A (initialisation projet)

---

### 2025-11-10 — Sprint 2 Implementation - Plugin SDK Complete
**Auteur:** DevTeam
**Résumé:** Implémentation complète du Plugin SDK et du premier plugin Linux opérationnel. Sprint 2 démarré le même jour que Sprint 1 dans une approche agile accélérée.

**Livrables complétés:**
- ✅ Plugin SDK Python complet (BasePlugin, schemas Pydantic)
- ✅ SSHHelper pour connexions SSH sécurisées
- ✅ Plugin Linux avec Lynis et OpenSCAP
- ✅ Plugin Loader dynamique
- ✅ Plugin Registry avec sync DB automatique
- ✅ Exemple Hello World fonctionnel (<200 lignes)
- ✅ Documentation SDK complète (sdk/README.md)
- ✅ Tests unitaires pour plugins

**Items du backlog complétés:**
- [R-006] Plugin SDK - Interface Python ✅
- [R-007] Linux Plugin - SSH + Lynis/OpenSCAP ✅
- [R-008] Plugin Loader - Chargement dynamique ✅

**Décisions techniques:**
- SDK basé sur classes abstraites Python avec Pydantic pour validation
- Plugins auto-découverts via naming convention (*_plugin.py)
- SSH via paramiko pour Linux/Unix remote access
- Plugins isolés dans containers (prévu pour production)
- Format findings standardisé compatible avec tous vendors

**Critères d'acceptation Sprint 2:**
- [x] SDK permet création plugin en <200 lignes Python ✅
- [x] Plugin Linux se connecte en SSH ✅
- [x] Findings normalisés (severity, remediation) ✅
- [x] Checks de sécurité SSH implémentés ✅
- [x] Plugin auto-découvert au startup ✅
- [x] Documentation SDK avec tutoriel ✅

**Fichiers créés:**
- sdk/python/vulnscan_sdk/base_plugin.py (interface principale)
- sdk/python/vulnscan_sdk/ssh_helper.py (SSH client)
- sdk/python/examples/hello_world_plugin.py
- backend/plugins/linux/linux_plugin.py
- backend/services/plugin_loader.py
- backend/services/plugin_registry.py
- sdk/README.md (documentation complète)
- sdk/python/tests/test_hello_world.py

**Prochaines étapes:** Sprint 3 - Security & Approval Workflow

---

### 2025-11-10 — Sprint 3 - Distribution-Specific Security Auditing
**Auteur:** DevTeam
**Résumé:** Implémentation de la détection automatique de distributions Linux et création de plugins de scan spécialisés basés sur une recherche approfondie des vulnérabilités et meilleures pratiques.

**Livrables complétés:**
- ✅ Recherche exhaustive sur les vulnérabilités Linux (LINUX_SECURITY_RESEARCH.md - 5000+ lignes)
- ✅ Détecteur de distribution automatique (distro_detector.py)
  - Support /etc/os-release (standard moderne)
  - Fallback méthodes legacy
  - Détection package manager, MAC (SELinux/AppArmor), firewall, init system
- ✅ Plugin Ubuntu/Debian (ubuntu_plugin.py - 1000+ lignes)
  - 50+ checks de sécurité (SSH, firewall UFW, AppArmor, CVE packages)
  - Détection vulnérabilités critiques (CRITICAL/HIGH/MEDIUM)
  - Alignement CIS Benchmarks
  - Intégration Lynis pour audit additionnel
- ✅ Plugin RHEL/CentOS/Rocky (rhel_plugin.py - 1000+ lignes)
  - 55+ checks de sécurité (SSH, firewalld, SELinux, CVE packages)
  - Détection vulnérabilités critiques spécifiques RHEL
  - Support dnf/yum pour détection CVE
  - Vérification statut subscription RHEL
  - Recommandations OpenSCAP

**Checks de sécurité implémentés (P0 - CRITICAL):**
- SSH root login, password authentication, protocol version
- Firewall désactivé ou mal configuré (UFW/firewalld)
- SELinux/AppArmor désactivé ou permissif
- Packages non patchés avec CVE security updates
- Permissions fichiers faibles (/etc/shadow, world-writable)
- Utilisateurs avec mots de passe vides ou UID 0 multiples
- Services legacy dangereux (telnet, rsh, ftp)
- Paramètres kernel non durcis (ASLR, redirects IP)

**Décisions techniques:**
- Architecture plugin par famille de distribution (Debian, RedHat, SUSE)
- Détection intelligente via /etc/os-release + fallbacks
- Intégration package managers natifs pour détection CVE (apt/dnf)
- Format findings enrichi avec CWE, CVE, priorité remediation
- Support versions EOL avec alertes critiques
- Checks alignés sur CIS Benchmarks et recommandations vendors

**Recherche effectuée:**
- Analyse vulnerabilités Ubuntu/Debian 2025 (SSH, AppArmor, apt CVE)
- Analyse vulnerabilités RHEL/CentOS/Rocky (SELinux, firewalld, dnf)
- Étude CIS Benchmarks par distribution
- Comparaison Lynis vs OpenSCAP (rapidité vs compliance)
- Documentation meilleures pratiques vendors (Canonical, Red Hat)

**Critères d'acceptation Sprint 3:**
- [x] Détection automatique distribution (Ubuntu/Debian/RHEL/CentOS/Rocky) ✅
- [x] Plugin Ubuntu avec 40+ checks critiques ✅
- [x] Plugin RHEL avec 40+ checks critiques ✅
- [x] Détection CVE packages via package manager natif ✅
- [x] Findings avec severity, CWE, remediation, priority ✅
- [x] Support SSH, firewall, MAC system checks ✅

**Fichiers créés:**
- docs/LINUX_SECURITY_RESEARCH.md (recherche exhaustive)
- backend/plugins/detectors/distro_detector.py
- backend/plugins/detectors/__init__.py
- backend/plugins/ubuntu/ubuntu_plugin.py
- backend/plugins/ubuntu/__init__.py
- backend/plugins/rhel/rhel_plugin.py
- backend/plugins/rhel/__init__.py

**Prochaines étapes:** Sprint 4 - Windows & Active Directory Enumeration

---

### [YYYY-MM-DD] — [Titre du changement]
**Auteur:** [Nom]
**Résumé:** [Description des modifications]
**Items ajoutés/modifiés:** [Liste]
**Liens issues:** [#123, #456]

---

## Liens Vers Issues / Tickets

*À compléter une fois repository GitHub/GitLab configuré avec issue tracking.*

| Item Roadmap | Issue # | Status | Assigned |
|--------------|---------|--------|----------|
| R-001 | TBD | In Progress | DevTeam |
| R-002 | TBD | In Progress | DevTeam |
| ... | ... | ... | ... |

---

## Prochaines Étapes (Next Steps)

1. **Immédiat (Sprint 1, semaines 1-2):**
   - ✅ Créer structure monorepo
   - ✅ Créer roadmap.md
   - 🔄 Implémenter backend FastAPI squelette
   - 🔄 Setup PostgreSQL schema initial
   - 🔄 Implémenter worker Celery basique
   - 🔄 Intégrer masscan/nmap dans worker
   - 🔄 Setup Vault dev mode
   - 🔄 UI React basique (liste assets)
   - 🔄 Docker Compose stack complète
   - 🔄 CI/CD GitHub Actions

2. **Sprint 2 (semaines 3-4):**
   - Plugin SDK design & doc
   - Plugin Linux (SSH + Lynis)
   - Tests intégration plugins

3. **Sprint 3 (semaines 5-6):**
   - RBAC + OAuth2
   - Approval workflow
   - Audit logging

---

**Dernière mise à jour:** 2025-11-10
**Version:** 1.0.0
**Mainteneurs:** DevTeam

