# Livrable 1 — Graphe Neo4j

---

## Capture d'écran du graphe Neo4j

![Graphe Neo4j CyberCorp](bloom-visualisation.png)

---

## Script Cypher de création des nœuds

```cypher
// --- Utilisateurs ---
CREATE (:User {name: "alice",   role: "RH",            department: "Ressources Humaines", email: "alice@cybercorp.fr"});
CREATE (:User {name: "bob",     role: "Développeur",   department: "IT",                  email: "bob@cybercorp.fr"});
CREATE (:User {name: "charlie", role: "Admin Système", department: "IT",                  email: "charlie@cybercorp.fr"});
CREATE (:User {name: "diana",   role: "RSSI",          department: "Sécurité",            email: "diana@cybercorp.fr"});
CREATE (:User {name: "eve",     role: "Stagiaire",     department: "Ressources Humaines", email: "eve@cybercorp.fr"});

// --- Machines ---
CREATE (:Machine {name: "PC-ALICE",   type: "workstation",       criticality: "low",      os: "Windows 10",           ip: "192.168.1.10", patched: false});
CREATE (:Machine {name: "PC-BOB",     type: "workstation",       criticality: "medium",   os: "Windows 10",           ip: "192.168.1.11", patched: false});
CREATE (:Machine {name: "PC-CHARLIE", type: "workstation",       criticality: "medium",   os: "Windows 11",           ip: "192.168.1.12", patched: true});
CREATE (:Machine {name: "SRV-WEB",    type: "server",            criticality: "medium",   os: "Ubuntu 20.04",         ip: "192.168.2.10", patched: false});
CREATE (:Machine {name: "SRV-MAIL",   type: "mail_server",       criticality: "medium",   os: "Windows Server 2019",  ip: "192.168.2.20", patched: false});
CREATE (:Machine {name: "SRV-DB",     type: "database",          criticality: "high",     os: "Ubuntu 22.04",         ip: "192.168.3.10", patched: false});
CREATE (:Machine {name: "DC-01",      type: "domain_controller", criticality: "critical", os: "Windows Server 2019",  ip: "192.168.4.10", patched: false});
CREATE (:Machine {name: "NAS-BACKUP", type: "backup_server",     criticality: "critical", os: "FreeNAS 12",           ip: "192.168.4.20", patched: false});

// --- Services ---
CREATE (:Service {name: "SSH",     port: 22,    protocol: "TCP"});
CREATE (:Service {name: "HTTP",    port: 80,    protocol: "TCP"});
CREATE (:Service {name: "HTTPS",   port: 443,   protocol: "TCP"});
CREATE (:Service {name: "RDP",     port: 3389,  protocol: "TCP"});
CREATE (:Service {name: "SMB",     port: 445,   protocol: "TCP"});
CREATE (:Service {name: "MongoDB", port: 27017, protocol: "TCP"});
CREATE (:Service {name: "SMTP",    port: 25,    protocol: "TCP"});

// --- Vulnérabilités ---
CREATE (:Vulnerability {cve: "CVE-2021-44228", name: "Log4Shell",           score: 10.0, description: "RCE via injection JNDI dans Apache Log4j",       remediation: "Mettre à jour Log4j >= 2.15.0"});
CREATE (:Vulnerability {cve: "CVE-2020-1472",  name: "Zerologon",           score: 10.0, description: "Élévation de privilèges vers SYSTEM sur DC",      remediation: "Appliquer le correctif KB4569742"});
CREATE (:Vulnerability {cve: "CVE-2019-0708",  name: "BlueKeep",            score: 9.8,  description: "RCE sans authentification via RDP",               remediation: "Désactiver RDP ou appliquer KB4499175"});
CREATE (:Vulnerability {cve: "CVE-2022-22965", name: "Spring4Shell",        score: 9.8,  description: "RCE via ClassLoader sur Spring MVC",              remediation: "Mettre à jour Spring Framework >= 5.3.18"});
CREATE (:Vulnerability {cve: "CVE-2023-0001",  name: "SMB Misconfiguration",score: 7.5,  description: "Partage SMB accessible sans authentification",    remediation: "Désactiver SMBv1, restreindre les partages anonymes"});
CREATE (:Vulnerability {cve: "CVE-2021-26855", name: "ProxyLogon",          score: 9.8,  description: "RCE pré-authentification sur Microsoft Exchange", remediation: "Appliquer le correctif Exchange KB5001779"});

// --- Groupes ---
CREATE (:Group {name: "RH",       description: "Utilisateurs des Ressources Humaines", permissions: "read"});
CREATE (:Group {name: "DEV",      description: "Équipe de développement",              permissions: "read-write"});
CREATE (:Group {name: "ADMINS",   description: "Administrateurs système",              permissions: "full"});
CREATE (:Group {name: "SECURITY", description: "Équipe sécurité (RSSI)",               permissions: "audit"});

// --- Ressources sensibles ---
CREATE (:Resource {name: "Base clients",        sensitivity: "high",     type: "database",    owner: "Commercial"});
CREATE (:Resource {name: "Données RH",          sensitivity: "high",     type: "database",    owner: "RH"});
CREATE (:Resource {name: "Active Directory",    sensitivity: "critical", type: "directory",   owner: "IT"});
CREATE (:Resource {name: "Sauvegardes",         sensitivity: "critical", type: "backup",      owner: "IT"});
CREATE (:Resource {name: "Secrets applicatifs", sensitivity: "critical", type: "credentials", owner: "DEV"});
```

---

## Script Cypher de création des relations

```cypher
// --- USES : utilisateur utilise une machine ---
MATCH (u:User {name:"alice"}),   (m:Machine {name:"PC-ALICE"})   CREATE (u)-[:USES]->(m);
MATCH (u:User {name:"eve"}),     (m:Machine {name:"PC-ALICE"})   CREATE (u)-[:USES]->(m);
MATCH (u:User {name:"bob"}),     (m:Machine {name:"PC-BOB"})     CREATE (u)-[:USES]->(m);
MATCH (u:User {name:"charlie"}), (m:Machine {name:"PC-CHARLIE"}) CREATE (u)-[:USES]->(m);
MATCH (u:User {name:"diana"}),   (m:Machine {name:"DC-01"})      CREATE (u)-[:USES]->(m);

// --- MEMBER_OF : utilisateur appartient à un groupe ---
MATCH (u:User {name:"alice"}),   (g:Group {name:"RH"})       CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name:"eve"}),     (g:Group {name:"RH"})       CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name:"bob"}),     (g:Group {name:"DEV"})      CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name:"charlie"}), (g:Group {name:"ADMINS"})   CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name:"diana"}),   (g:Group {name:"SECURITY"}) CREATE (u)-[:MEMBER_OF]->(g);

// --- ADMIN_OF : utilisateur administre une machine ---
MATCH (u:User {name:"charlie"}), (m:Machine {name:"DC-01"})      CREATE (u)-[:ADMIN_OF]->(m);
MATCH (u:User {name:"charlie"}), (m:Machine {name:"NAS-BACKUP"}) CREATE (u)-[:ADMIN_OF]->(m);
MATCH (u:User {name:"charlie"}), (m:Machine {name:"SRV-DB"})     CREATE (u)-[:ADMIN_OF]->(m);
MATCH (u:User {name:"charlie"}), (m:Machine {name:"SRV-WEB"})    CREATE (u)-[:ADMIN_OF]->(m);
MATCH (u:User {name:"charlie"}), (m:Machine {name:"SRV-MAIL"})   CREATE (u)-[:ADMIN_OF]->(m);

// --- CONNECTED_TO : connexions réseau entre machines ---
MATCH (a:Machine {name:"PC-ALICE"}),   (b:Machine {name:"SRV-WEB"})    CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name:"PC-ALICE"}),   (b:Machine {name:"SRV-MAIL"})   CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name:"PC-BOB"}),     (b:Machine {name:"SRV-WEB"})    CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name:"PC-BOB"}),     (b:Machine {name:"SRV-DB"})     CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name:"PC-CHARLIE"}), (b:Machine {name:"DC-01"})      CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name:"PC-CHARLIE"}), (b:Machine {name:"NAS-BACKUP"}) CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name:"SRV-WEB"}),    (b:Machine {name:"SRV-DB"})     CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name:"SRV-MAIL"}),   (b:Machine {name:"SRV-DB"})     CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name:"SRV-DB"}),     (b:Machine {name:"DC-01"})      CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name:"SRV-DB"}),     (b:Machine {name:"NAS-BACKUP"}) CREATE (a)-[:CONNECTED_TO]->(b);

// --- EXPOSES : machine expose un service réseau ---
MATCH (m:Machine {name:"SRV-WEB"}),    (s:Service {name:"HTTP"})    CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name:"SRV-WEB"}),    (s:Service {name:"HTTPS"})   CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name:"SRV-WEB"}),    (s:Service {name:"SSH"})     CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name:"SRV-MAIL"}),   (s:Service {name:"SMTP"})    CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name:"SRV-MAIL"}),   (s:Service {name:"HTTPS"})   CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name:"SRV-DB"}),     (s:Service {name:"MongoDB"}) CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name:"SRV-DB"}),     (s:Service {name:"SSH"})     CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name:"DC-01"}),      (s:Service {name:"SMB"})     CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name:"DC-01"}),      (s:Service {name:"RDP"})     CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name:"NAS-BACKUP"}), (s:Service {name:"SMB"})     CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name:"PC-BOB"}),     (s:Service {name:"RDP"})     CREATE (m)-[:EXPOSES]->(s);

// --- HAS_VULNERABILITY : machine affectée par une CVE ---
MATCH (m:Machine {name:"SRV-WEB"}),    (v:Vulnerability {cve:"CVE-2021-44228"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name:"SRV-WEB"}),    (v:Vulnerability {cve:"CVE-2022-22965"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name:"SRV-MAIL"}),   (v:Vulnerability {cve:"CVE-2021-26855"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name:"PC-BOB"}),     (v:Vulnerability {cve:"CVE-2019-0708"})  CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name:"DC-01"}),      (v:Vulnerability {cve:"CVE-2020-1472"})  CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name:"NAS-BACKUP"}), (v:Vulnerability {cve:"CVE-2023-0001"})  CREATE (m)-[:HAS_VULNERABILITY]->(v);

// --- HAS_ACCESS_TO : groupe a accès à une machine ---
MATCH (g:Group {name:"RH"}),       (m:Machine {name:"SRV-WEB"})    CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name:"RH"}),       (m:Machine {name:"SRV-MAIL"})   CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name:"DEV"}),      (m:Machine {name:"SRV-WEB"})    CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name:"DEV"}),      (m:Machine {name:"SRV-DB"})     CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name:"ADMINS"}),   (m:Machine {name:"DC-01"})      CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name:"ADMINS"}),   (m:Machine {name:"NAS-BACKUP"}) CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name:"ADMINS"}),   (m:Machine {name:"SRV-DB"})     CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name:"SECURITY"}), (m:Machine {name:"DC-01"})      CREATE (g)-[:HAS_ACCESS_TO]->(m);

// --- HOSTS : machine héberge une ressource sensible ---
MATCH (m:Machine {name:"SRV-DB"}),     (r:Resource {name:"Base clients"})        CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name:"SRV-DB"}),     (r:Resource {name:"Secrets applicatifs"}) CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name:"SRV-MAIL"}),   (r:Resource {name:"Données RH"})          CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name:"DC-01"}),      (r:Resource {name:"Active Directory"})    CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name:"NAS-BACKUP"}), (r:Resource {name:"Sauvegardes"})         CREATE (m)-[:HOSTS]->(r);
```

---

## Description du modèle de données

Le graphe représente le SI de CyberCorp avec **35 nœuds** et **55 relations** de 6 types : `:User`, `:Machine`, `:Service`, `:Vulnerability`, `:Group`, `:Resource`.

Les relations modélisent les interactions du SI : qui utilise quelle machine (`USES`), les connexions réseau (`CONNECTED_TO`), les services exposés (`EXPOSES`), les vulnérabilités connues (`HAS_VULNERABILITY`) et les ressources hébergées (`HOSTS`).

La relation `CONNECTED_TO` est centrale : elle permet d'identifier les chemins d'attaque depuis PC-ALICE vers les ressources critiques via `shortestPath()`.