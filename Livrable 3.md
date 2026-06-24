# Rapport d'analyse cyber — CyberCorp

## 1. Présentation du système d'information modélisé

CyberCorp possède une infrastructure composée de 5 utilisateurs, 8 machines, 4 groupes, 7 services, 6 vulnérabilités et 5 ressources sensibles, modélisée dans Neo4j avec 35 nœuds et 55 relations.

---

## 2. Schéma ou capture du graphe

![Graphe Neo4j CyberCorp](bloom-visualisation.png)

---

## 3. Hypothèse d'attaque

Le poste **PC-ALICE** est compromis à la suite d'une attaque par phishing ciblant l'utilisatrice alice (RH). La machine est également utilisée par eve (Stagiaire), ce qui expose deux comptes simultanément.

---

## 4. Chemins d'attaque identifiés

Depuis PC-ALICE, un attaquant peut atteindre SRV-WEB, puis SRV-DB, puis DC-01.

Le serveur SRV-WEB expose HTTP et HTTPS et possède une vulnérabilité critique Log4Shell (CVE-2021-44228, CVSS 10.0) permettant une exécution de code à distance.

Le serveur SRV-DB héberge la base clients et les secrets applicatifs.

SRV-DB est connecté au contrôleur de domaine DC-01, ce qui représente un risque très élevé. DC-01 est vulnérable à Zerologon (CVE-2020-1472, CVSS 10.0), permettant une prise de contrôle totale de l'Active Directory.

Un chemin alternatif existe via SRV-MAIL (ProxyLogon, CVE-2021-26855), qui mène également à SRV-DB puis DC-01.

---

## 5. Machines vulnérables

| Machine | Vulnérabilité | CVSS |
|---|---|---|
| SRV-WEB | Log4Shell (CVE-2021-44228) | 10.0 |
| DC-01 | Zerologon (CVE-2020-1472) | 10.0 |
| SRV-MAIL | ProxyLogon (CVE-2021-26855) | 9.8 |
| PC-BOB | BlueKeep (CVE-2019-0708) | 9.8 |
| NAS-BACKUP | SMB Misconfiguration (CVE-2023-0001) | 7.5 |

---

## 6. Services exposés

SRV-WEB expose HTTP (80), HTTPS (443) et SSH (22). SRV-DB expose MongoDB (27017) sans authentification. DC-01 expose SMB (445) et RDP (3389). NAS-BACKUP expose SMB (445), ce qui permet un accès non authentifié aux sauvegardes.

---

## 7. Utilisateurs et groupes à risque

Le groupe **DEV** possède un accès à SRV-DB alors que cet accès devrait être limité.

Le groupe **ADMINS** possède des droits sur DC-01 et NAS-BACKUP. charlie est le seul administrateur système : une compromission de son compte mènerait à une compromission complète du SI.

alice et eve partagent le poste PC-ALICE : un phishing sur l'une expose les deux comptes.

---

## 8. Recommandations de sécurité

- Isoler PC-ALICE du réseau et réinitialiser les comptes alice et eve.
- Corriger Log4Shell sur SRV-WEB (CVE-2021-44228).
- Corriger Zerologon sur DC-01 (CVE-2020-1472).
- Corriger ProxyLogon sur SRV-MAIL (CVE-2021-26855).
- Limiter les connexions directes vers SRV-DB.
- Revoir les droits du groupe DEV sur SRV-DB.
- Appliquer le principe du moindre privilège.
- Segmenter le réseau en VLANs.
- Désactiver les services non nécessaires (RDP sur DC-01, SMB anonyme sur NAS-BACKUP).
- Renforcer l'authentification des comptes administrateurs (MFA).
- Surveiller les connexions anormales entre zones.

---

## 9. Conclusion

L'absence de segmentation réseau permet d'atteindre DC-01 en seulement 3 sauts depuis un poste utilisateur compromis. La combinaison de Log4Shell et Zerologon non corrigés forme une chaîne d'attaque directe vers l'Active Directory, ce qui représente un risque de compromission totale du SI.