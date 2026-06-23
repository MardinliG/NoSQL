# Livrable 2 — Requêtes Cypher

---

## 1. Requêtes de création

### Création d'un utilisateur
```cypher
CREATE (:User {name: "alice", role: "RH", department: "Ressources Humaines", email: "alice@cybercorp.fr"});
```
**Résultat :** 1 nœud `:User` créé.
**Commentaire :** Crée le compte alice avec son rôle et ses informations. Chaque utilisateur est un nœud indépendant dans le graphe.

---

### Création d'une machine
```cypher
CREATE (:Machine {name: "DC-01", type: "domain_controller", criticality: "critical", os: "Windows Server 2019", ip: "192.168.4.10", patched: false});
```
**Résultat :** 1 nœud `:Machine` créé.
**Commentaire :** La propriété `criticality: "critical"` et `patched: false` indiquent que DC-01 est une cible prioritaire non corrigée.

---

### Création d'une vulnérabilité
```cypher
CREATE (:Vulnerability {cve: "CVE-2020-1472", name: "Zerologon", score: 10.0, description: "Élévation de privilèges vers SYSTEM sur DC", remediation: "Appliquer le correctif KB4569742"});
```
**Résultat :** 1 nœud `:Vulnerability` créé.
**Commentaire :** Zerologon est la vulnérabilité la plus critique du SI avec un score CVSS maximum de 10.0.

---

## 2. Requêtes d'analyse

### Requête 1 — Utilisateurs et leurs machines
```cypher
MATCH (u:User)-[:USES]->(m:Machine)
RETURN u.name AS utilisateur, u.role AS role, m.name AS machine, m.criticality AS criticite
ORDER BY m.criticality DESC;
```

**Résultat :**

| utilisateur | role | machine | criticite |
|---|---|---|---|
| diana | RSSI | DC-01 | critical |
| alice | RH | PC-ALICE | low |
| eve | Stagiaire | PC-ALICE | low |
| bob | Développeur | PC-BOB | medium |
| charlie | Admin Système | PC-CHARLIE | medium |

**Commentaire :** Alice et eve partagent le même poste PC-ALICE. Un phishing ciblant l'une des deux compromet les deux comptes simultanément.

---

### Requête 2 — Machines vulnérables classées par score CVSS
```cypher
MATCH (m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN m.name AS machine, v.cve AS cve, v.name AS vulnerabilite, v.score AS score
ORDER BY v.score DESC;
```

**Résultat :**

| machine | cve | vulnerabilite | score |
|---|---|---|---|
| SRV-WEB | CVE-2021-44228 | Log4Shell | 10.0 |
| DC-01 | CVE-2020-1472 | Zerologon | 10.0 |
| SRV-WEB | CVE-2022-22965 | Spring4Shell | 9.8 |
| SRV-MAIL | CVE-2021-26855 | ProxyLogon | 9.8 |
| PC-BOB | CVE-2019-0708 | BlueKeep | 9.8 |
| NAS-BACKUP | CVE-2023-0001 | SMB Misconfiguration | 7.5 |

**Commentaire :** 6 CVE actives non corrigées dans le SI. SRV-WEB cumule deux failles critiques. Log4Shell sur SRV-WEB et Zerologon sur DC-01 forment ensemble la chaîne d'attaque principale.

---

### Requête 3 — Chemin le plus court vers DC-01 depuis PC-ALICE
```cypher
MATCH path = shortestPath(
  (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*]->(target:Machine {name: "DC-01"})
)
RETURN [node IN nodes(path) | node.name] AS chemin, length(path) AS nb_sauts;
```

**Résultat :**

| chemin | nb_sauts |
|---|---|
| ["PC-ALICE", "SRV-WEB", "SRV-DB", "DC-01"] | 3 |

**Commentaire :** Seulement 3 sauts séparent le poste compromis du contrôleur de domaine. Une fois DC-01 atteint via Zerologon, l'attaquant prend le contrôle total de l'Active Directory et donc de tout le SI.

---

### Requête 4 — Toutes les ressources critiques accessibles depuis PC-ALICE
```cypher
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HOSTS]->(r:Resource)
RETURN r.name AS ressource, r.sensitivity AS sensibilite, m.name AS machine,
       [node IN nodes(path) WHERE node:Machine | node.name] AS chemin
ORDER BY r.sensitivity DESC;
```

**Résultat :**

| ressource | sensibilite | machine | chemin |
|---|---|---|---|
| Active Directory | critical | DC-01 | ["PC-ALICE", "SRV-WEB", "SRV-DB", "DC-01"] |
| Sauvegardes | critical | NAS-BACKUP | ["PC-ALICE", "SRV-WEB", "SRV-DB", "NAS-BACKUP"] |
| Secrets applicatifs | critical | SRV-DB | ["PC-ALICE", "SRV-WEB", "SRV-DB"] |
| Base clients | high | SRV-DB | ["PC-ALICE", "SRV-WEB", "SRV-DB"] |
| Données RH | high | SRV-MAIL | ["PC-ALICE", "SRV-MAIL"] |

**Commentaire :** Toutes les ressources sensibles du SI sont accessibles depuis PC-ALICE. Les Données RH sont atteignables en un seul saut via SRV-MAIL.

---

### Requête 5 — Utilisateurs pouvant accéder à des machines critiques via leur groupe
```cypher
MATCH (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_ACCESS_TO]->(m:Machine)
WHERE m.criticality IN ["high", "critical"]
RETURN u.name AS utilisateur, g.name AS groupe, m.name AS machine, m.criticality AS criticite
ORDER BY m.criticality DESC;
```

**Résultat :**

| utilisateur | groupe | machine | criticite |
|---|---|---|---|
| charlie | ADMINS | DC-01 | critical |
| diana | SECURITY | DC-01 | critical |
| charlie | ADMINS | NAS-BACKUP | critical |
| charlie | ADMINS | SRV-DB | high |
| bob | DEV | SRV-DB | high |

**Commentaire :** Bob accède à SRV-DB via le groupe DEV alors qu'il est développeur — violation du principe du moindre privilège. Charlie est le seul administrateur avec accès à toute l'infrastructure critique, ce qui en fait un point de défaillance unique.

---

### Requête 6 — Score de risque par machine
```cypher
MATCH (m:Machine)
OPTIONAL MATCH (m)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WITH m, max(v.score) AS score_max,
  CASE m.criticality WHEN "critical" THEN 3.0 WHEN "high" THEN 2.0 WHEN "medium" THEN 1.5 ELSE 1.0 END AS mult,
  CASE m.patched WHEN false THEN 2.5 ELSE 0.0 END AS penalite
RETURN m.name AS machine, m.criticality AS criticite,
  round((coalesce(score_max,0) * mult + penalite) * 10) / 10 AS score_risque
ORDER BY score_risque DESC;
```

**Résultat :**

| machine | criticite | score_risque |
|---|---|---|
| DC-01 | critical | 32.5 |
| NAS-BACKUP | critical | 25.0 |
| SRV-WEB | medium | 17.5 |
| SRV-MAIL | medium | 17.2 |
| PC-BOB | medium | 17.2 |
| SRV-DB | high | 2.5 |
| PC-ALICE | low | 2.5 |
| PC-CHARLIE | medium | 0.0 |

**Commentaire :** DC-01 est la machine la plus à risque (score 32.5) car elle combine une criticité maximale, Zerologon CVSS 10 et l'absence de patch. Ce scoring permet de prioriser les actions correctives : DC-01 et NAS-BACKUP en urgence absolue.