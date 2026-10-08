# 🌐 HTTP Response Advanced Scanner

**Auteur:** `hackers_tchad`  
**Version:** 4.0.0

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Scanner HTTP multi-URLs / multi-ports avancé** capable d'envoyer des requêtes `GET` vers une ou plusieurs URLs complètes sur des dizaines, centaines ou milliers de ports et de chemins, de collecter les réponses, d'afficher un **compteur de progression**, et d'exporter des rapports riches en **JSON / CSV / TXT / HTML / Markdown / XML / SQLite**.

---

## 📋 Table des matières

1. [Fonctionnalités](#-fonctionnalités)
2. [Installation](#-installation)
3. [Utilisation rapide](#-utilisation-rapide)
4. [Exemples avancés](#-exemples-avancés)
5. [Options CLI](#-options-cli)
6. [Formats de sortie](#-formats-de-sortie)
7. [Architecture](#-architecture)
8. [Dépendances](#-dépendances)
9. [Avertissement légal](#-avertissement-légal)
10. [Auteur](#-auteur)

---

## ✨ Fonctionnalités

| Fonctionnalité | Description |
|----------------|-------------|
| 🔗 **URL-first** | Scan par URL complète, cible, ou fichier de cibles/URLs. |
| 🔍 **Multi-ports** | Scan de listes personnalisées, top 100 ports web, ou tous les ports communs. |
| 📁 **Multi-paths** | Scan de plusieurs chemins par endpoint (`/`, `/admin`, `/api`...). |
| ⚡ **Double moteur** | Mode synchrone (`requests`) ou asynchrone (`aiohttp`) ultra-rapide. |
| 🧵 **Multi-threading** | Jusqu'à plusieurs centaines de workers simultanés. |
| 🎭 **User-Agents** | Rotation aléatoire ou User-Agent personnalisé. |
| 🔒 **SSL flexible** | Vérification activable/désactivable, suivi des redirections, infos certificat. |
| 🧱 **Proxies** | Support HTTP/HTTPS/SOCKS avec rotation. |
| 🔄 **Retry & backoff** | Tentatives automatiques avec backoff exponentiel et jitter. |
| 🎯 **Filtres avancés** | Par status, temps, taille, mots-clés, regex. |
| 🧬 **Fingerprinting** | Détection des technologies, CMS, frameworks, serveurs. |
| 💾 **Exports riches** | JSON, CSV, TXT, HTML, Markdown, XML, SQLite. |
| 🖥️ **CLI colorée** | Barre de progression, compteur, tableau de résultats. |
| 📝 **Logs** | Niveaux silencieux, verbeux, debug. |
| 🔔 **Webhook** | Notification de fin de scan vers une URL externe. |
| 🧪 **Dry-run** | Générer les URLs sans envoyer de requêtes. |

---

## 🚀 Installation

### 1. Cloner ou copier les fichiers

```bash
git clone <repo>        # ou copie manuelle des fichiers
cd http-response-scanner
```

### 2. Créer un environnement virtuel (recommandé)

```bash
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
# venv\Scripts\activate    # Windows
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 4. Vérifier l'installation

```bash
python http_response_scanner.py --version
```

---

## 🎯 Utilisation rapide

Scanner les ports par défaut sur `example.com` :

```bash
python http_response_scanner.py -t example.com
```

Scanner des ports spécifiques avec export JSON :

```bash
python http_response_scanner.py -t example.com -p 80,443,8080,8443 -o report.json -f json
```

Scanner les 100 ports web les plus courants en mode asynchrone :

```bash
python http_response_scanner.py -t example.com -p top100 -T 200 --async
```

---

## 🔥 Exemples avancés

### Avec rotation User-Agent et proxy

```bash
python http_response_scanner.py \
  -t cible.example.com \
  -p 80,443,8080-8090 \
  --random-user-agent \
  --proxy http://127.0.0.1:8080 \
  --proxy-rotate \
  -T 100
```

### Filtrer uniquement les réponses 200 et 301

```bash
python http_response_scanner.py \
  -t cible.example.com \
  -p top100 \
  --filter-status 200,301 \
  -o filtered.json
```

### Mode asynchrone avec 500 workers, exports HTML

```bash
python http_response_scanner.py \
  -t cible.example.com \
  -p all \
  --async \
  -T 500 \
  --no-verify-ssl \
  --random-user-agent \
  -f html \
  -o report.html
```

### Authentification Bearer + cookies

```bash
python http_response_scanner.py \
  -t api.example.com \
  -p 443,8443 \
  --auth-bearer "eyJhbGciOiJIUzI1NiIs..." \
  --cookies "session=abc123; lang=fr"
```

---

## 🛠️ Options CLI

| Option | Description |
|--------|-------------|
| `-t`, `--target` | Hôte cible (domaine ou IP). Répétable. |
| `-u`, `--url` | URL complète. Répétable. |
| `-f`, `--target-file` | Fichier avec une cible ou URL par ligne. |
| `-p`, `--ports` | Liste de ports, `top100`, `web`, `all`, ou plages `8000-8010`. |
| `--paths` | Chemins à scanner séparés par virgules (défaut: `/`). |
| `--path-file` | Fichier de chemins (un par ligne). |
| `--timeout` | Timeout en secondes (défaut: 10). |
| `-T`, `--threads` | Nombre de threads/concurrences (défaut: 50). |
| `--ssl` | Préférer HTTPS sur les ports non standards. |
| `--no-verify-ssl` | Désactiver la vérification du certificat SSL. |
| `--no-follow-redirects` | Ne pas suivre les redirections HTTP. |
| `--max-redirects` | Nombre maximum de redirections. |
| `--random-user-agent` | Activer la rotation aléatoire des User-Agents. |
| `--user-agent` | Définir un User-Agent fixe. |
| `-H`, `--headers` | Ajouter un header personnalisé (`Key: Value`). Répétable. |
| `--proxy` | Proxy à utiliser. Répétable. |
| `--proxy-rotate` | Rotation aléatoire entre les proxies fournis. |
| `-o`, `--output` | Chemin du fichier de sortie. |
| `-f`, `--format` | Format de sortie: `json`, `csv`, `txt`, `html`, `md`, `xml`, `sqlite`. |
| `-s`, `--silent` | Mode silencieux (logs dans `scanner.log`). |
| `-v`, `--verbose` | Afficher plus d'informations. |
| `-d`, `--debug` | Mode debug très verbeux. |
| `--filter-status` | Garder uniquement ces status (ex: `200,301` ou `200-299`). |
| `--exclude-status` | Exclure ces status. |
| `--min-time` / `--max-time` | Filtrer par temps de réponse (ms). |
| `--min-size` / `--max-size` | Filtrer par taille du corps (bytes). |
| `--save-body` | Sauvegarder les corps de réponse dans `--body-dir`. |
| `--body-dir` | Répertoire de sauvegarde des corps (défaut: `./bodies`). |
| `--async` | Utiliser le moteur asynchrone `aiohttp`. |
| `--retries` | Nombre de tentatives en cas d'échec. |
| `--backoff` | Facteur de backoff exponentiel. |
| `--no-jitter` | Désactiver le jitter en mode async. |
| `--no-dns-cache` | Désactiver le cache DNS interne. |
| `--cookies` | Cookies bruts à envoyer. |
| `--auth-basic` | Authentification Basic (`user:pass`). |
| `--auth-bearer` | Token Bearer. |
| `--scheme` | Forcer `http` ou `https`. |
| `--source-ip` | IP source à binder (si supporté par l'OS). |
| `--tcp-pre-check` | Vérifier si le port TCP est ouvert avant requête. |
| `--dry-run` | Générer les URLs sans envoyer de requêtes. |
| `--keyword` | Mot-clé à rechercher dans le body. Répétable. |
| `--exclude-keyword` | Mot-clé excluant. Répétable. |
| `--regex` | Regex à rechercher dans le body/title. |
| `--resolve-ip` | Résoudre l'IP de chaque cible. |
| `--full-chain` | Récupérer les informations du certificat SSL. |
| `--webhook` | URL webhook pour notification de fin de scan. |

---

## 📤 Formats de sortie

### JSON

```json
{
  "metadata": { "tool": "HTTP Response Advanced Scanner", ... },
  "results": [
    {
      "target": "example.com",
      "port": 443,
      "url": "https://example.com:443/",
      "status_code": 200,
      "response_time_ms": 45.231,
      "content_length": 1256,
      "title": "Example Domain",
      "technologies": ["Nginx", "Cloudflare"]
    }
  ],
  "summary": { "total_scanned": 100, "alive": 12, ... }
}
```

### CSV

Fichier plat avec une ligne par résultat et les colonnes du dataclass `ScanResult`.

### HTML

Rapport visuel complet avec tableau coloré, statuts colorés, liens cliquables et résumé.

### Markdown

Tableau Markdown prêt à être intégré dans une documentation ou un rapport.

### TXT

Format texte lisible avec détails complets par endpoint.

---

## 🏗️ Architecture

Le script est monolithique mais structuré en classes responsables :

| Classe | Rôle |
|--------|------|
| `Colors` | Codes ANSI et gestion cross-platform. |
| `NetworkHelpers` | Parsing, résolution DNS, construction d'URL, extraction de titre/tech. |
| `RequestEngine` | Envoi des requêtes GET sync (`requests`) et async (`aiohttp`). |
| `ResultFilter` | Filtrage des résultats selon les critères utilisateur. |
| `ResultFormatter` | Formatage console coloré. |
| `Exporter` | Export JSON/CSV/TXT/HTML/Markdown/XML/SQLite. |
| `WebhookNotifier` | Envoi d'une notification de fin de scan. |
| `StatisticsReporter` | Résumé statistique final. |
| `ScannerOrchestrator` | Coordination du scan complet. |

---

## 📦 Dépendances

Les dépendances principales sont listées dans [`requirements.txt`](requirements.txt) :

- `requests` : moteur HTTP synchrone
- `aiohttp` : moteur HTTP asynchrone
- `urllib3` : retry, pool et SSL
- `colorama` : couleurs Windows
- `beautifulsoup4` & `lxml` : parsing optionnel

---

## ⚠️ Avertissement légal

> Ce logiciel est fourni à des fins éducatives et de test d'intrusion **légal** uniquement.  
> L'utilisateur est seul responsable de l'usage qui est fait de cet outil.  
> **Ne scannez jamais un système sans autorisation écrite explicite de son propriétaire.**

---

## 👤 Auteur

Développé par **hackers_tchad**.

## 📝 Licence

MIT License — voir le fichier `LICENSE` pour plus de détails.
