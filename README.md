
# spring-boot-analyse-cve

## Description

Ce projet est une application Spring Boot qui analyse les vulnérabilités CVE (Common Vulnerabilities and Exposures) sur des hôtes en utilisant Nmap pour scanner les ports et rechercher les services vulnérables.

## Fonctionnalités

- **Scan réseau** : Utilisation de Nmap pour scanner les hôtes et les ports.
- **Analyse des services** : Extraction des informations de service à partir des résultats de Nmap.
- **Recherche de CVE** : Recherche des vulnérabilités CVE pour les services identifiés.
- **Rapport** : Envoi des résultats de l'analyse à un service externe.

## Prérequis

- Java 11 ou supérieur
- Maven
- Nmap installé et accessible depuis la ligne de commande

## Installation

1. Clonez le dépôt :
   ```bash
   git clone https://github.com/Uqac-Atelier-Cyber-Project/spring-boot-analyse-cve.git
   cd spring-boot-analyse-cve
   ```

2. Compilez le projet avec Maven :
   ```bash
   mvn clean install
   ```

## Utilisation

1. Lancez l'application Spring Boot :
   ```bash
   mvn spring-boot:run
   ```

2. Envoyez une requête pour démarrer un scan (exemple avec `curl`) :
   ```bash
   curl -X POST http://localhost:8085/scan -H "Content-Type: application/json" -d '{"option": "votre_option", "reportId": "votre_report_id"}'
   ```

## Structure du projet

- `src/main/java/com/uqac/analyse_cve/AnalyseCveApplication.java` : Classe principale pour démarrer l'application Spring Boot.
- `src/main/java/com/uqac/analyse_cve/service/FunctionnalSystemService.java` : Service principal pour gérer le scan et l'analyse des CVE.
- `src/main/java/com/uqac/analyse_cve/service/NetworkScannerService.java` : Service pour exécuter Nmap.
- `src/main/java/com/uqac/analyse_cve/service/NmapParserService.java` : Service pour parser les résultats XML de Nmap.
- `src/main/java/com/uqac/analyse_cve/service/CveLookupService.java` : Service pour rechercher les CVE.
