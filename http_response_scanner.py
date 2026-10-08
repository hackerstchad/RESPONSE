#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    HTTP RESPONSE ADVANCED SCANNER v4.0                       ║
║                    URL-First Multi-Endpoint GET Engine                       ║
║                         Author: hackers_tchad                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

Description:
    Script Python ultra-avancé permettant d'envoyer des requêtes HTTP GET
    vers une ou plusieurs URLs complètes, sur plusieurs ports, avec gestion
    avancée des réponses, compteurs dynamiques, exports riches et détection
    de technologies.

Fonctionnalités principales:
    - Scan URL-first: URLs complètes, liste de cibles via fichier
    - Multi-ports synchrones/asynchrones avec génération automatique d'URLs
    - Rotation User-Agent, headers personnalisables, payloads
    - Support proxy HTTP/HTTPS/SOCKS4/SOCKS5 avec rotation
    - Retry exponentiel, jitter, DNS cache, TCP pre-check optionnel
    - Validation SSL optionnelle, suivi des redirections
    - Export JSON / CSV / TXT / HTML / Markdown / XML / SQLite
    - Fingerprinting technologies, CMS, frameworks, serveurs
    - Filtrage par status, taille, temps, mots-clés, regex
    - Compteur dynamique, barre de progression, tableau coloré
    - Logging avancé, statistiques, rapports automatiques
    - Mode silencieux, verbeux, debug, dry-run
    - Génération de wordlists de ports et de paths
    - Sauvegarde des corps de réponse, screenshots (optionnel)
    - Notifications webhook (optionnel)
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import datetime
import hashlib
import html
import ipaddress
import json
import logging
import os
import queue
import random
import re
import socket
import sqlite3
import ssl
import string
import sys
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

# ═══════════════════════════════════════════════════════════════════════════════
# Gestion optionnelle des dépendances tierces
# ═══════════════════════════════════════════════════════════════════════════════
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import colorama
    colorama.init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════════════════
# Constantes globales
# ═══════════════════════════════════════════════════════════════════════════════
VERSION = "4.0.0"
BUILD_DATE = "2025-01-20"
AUTHOR = "hackers_tchad"
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 50
DEFAULT_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]
MAX_REDIRECTS = 5
CHUNK_SIZE = 8192
MAX_BODY_STORAGE = 5 * 1024 * 1024

BANNER = r"""
    ██╗  ██╗████████╗████████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
    ███████║   ██║      ██║   ██████╔╝    ███████╗██║     ███████║██╔██╗ ██║
    ██╔══██║   ██║      ██║   ██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║  ██║   ██║      ██║   ██║         ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
        ╔══════════════════════════════════════════════════════════════════╗
        ║     HTTP RESPONSE ADVANCED SCANNER v4.0  |  Author: hackers_tchad ║
        ╚══════════════════════════════════════════════════════════════════╝
"""

# ═══════════════════════════════════════════════════════════════════════════════
# Palettes de couleurs
# ═══════════════════════════════════════════════════════════════════════════════
class Colors:
    """Codes couleurs ANSI multiplateformes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    ORANGE = "\033[38;5;208m"
    PINK = "\033[38;5;205m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"

    @classmethod
    def disable(cls) -> None:
        for attr in dir(cls):
            if not attr.startswith("_") and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, "")


# ═══════════════════════════════════════════════════════════════════════════════
# Base de données embarquée : User-Agents, ports, signatures
# ═══════════════════════════════════════════════════════════════════════════════
USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "curl/8.4.0",
    "Wget/1.21.4 (linux-gnu)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

COMMON_WEB_PORTS: List[int] = [
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
    443, 444, 445, 446, 447, 448, 449, 450,
    591, 593, 832, 833, 900, 901, 902, 903,
    1080, 1081, 1082, 1083,
    2000, 2001, 2002, 2003, 2004, 2005,
    3000, 3001, 3002, 3003, 3004, 3005,
    4000, 4001, 4002, 4003, 4004, 4005,
    5000, 5001, 5002, 5003, 5004, 5005,
    6000, 6001, 6002, 6003, 6004, 6005,
    7000, 7001, 7002, 7003, 7004, 7005,
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
    8100, 8443, 8444, 8445, 8446, 8447, 8448, 8449, 8450,
    8888, 8889, 8890, 8891, 8892, 8893,
    9000, 9001, 9002, 9003, 9004, 9005,
    9090, 9091, 9092, 9093, 9094, 9095,
    9200, 9300, 9443, 9800,
]

TECH_FINGERPRINTS: Dict[str, List[str]] = {
    "Apache": ["Apache", "apache"],
    "Nginx": ["nginx"],
    "IIS": ["Microsoft-IIS"],
    "Cloudflare": ["cloudflare", "CF-RAY"],
    "Akamai": ["AkamaiGHost", "Akamai"],
    "Fastly": ["Fastly"],
    "Gunicorn": ["gunicorn"],
    "Express": ["Express"],
    "PHP": ["PHP/", "X-Powered-By: PHP"],
    "ASP.NET": ["ASP.NET", "X-AspNet-Version"],
    "Django": ["WSGIServer", "django"],
    "Ruby on Rails": ["Rails", "Phusion Passenger"],
    "Caddy": ["Caddy"],
    "LiteSpeed": ["LiteSpeed"],
    "Tomcat": ["Apache-Coyote", "Tomcat"],
    "Jetty": ["Jetty"],
    "Node.js": ["Node.js"],
    "Go": ["Go-http-client", "Go"],
    "Python": ["Python/"],
    "WordPress": ["/wp-content/", "/wp-includes/", "WordPress"],
    "Joomla": ["Joomla"],
    "Drupal": ["Drupal"],
    "Laravel": ["Laravel"],
    "Spring": ["Spring"],
    "React": ["react", "__REACT"],
    "Vue.js": ["vue", "__VUE"],
    "Angular": ["ng-version", "angular"],
}

COMMON_PATHS: List[str] = [
    "/", "/admin", "/login", "/api", "/test", "/dev", "/staging",
    "/portal", "/dashboard", "/console", "/manager", "/phpmyadmin",
    "/wp-admin", "/wp-login.php", "/administrator", "/robots.txt",
    "/sitemap.xml", "/.env", "/.git/config", "/.htaccess",
    "/api/v1", "/api/v2", "/swagger", "/api-docs", "/graphql",
]

# ═══════════════════════════════════════════════════════════════════════════════
# Structures de données
# ═══════════════════════════════════════════════════════════════════════════════
@dataclass
class ScanResult:
    """Représente le résultat d'une requête GET sur une URL donnée."""
    target: str
    port: int
    url: str
    scheme: str
    status_code: int = 0
    reason: str = ""
    response_time_ms: float = 0.0
    content_length: int = -1
    headers: Dict[str, str] = field(default_factory=dict)
    title: str = ""
    body_snippet: str = ""
    technologies: List[str] = field(default_factory=list)
    error_message: str = ""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    final_url: str = ""
    redirect_count: int = 0
    server: str = ""
    content_type: str = ""
    hash_md5: str = ""
    hash_sha256: str = ""
    is_alive: bool = False
    is_ssl: bool = False
    proxy_used: str = ""
    method: str = "GET"
    path: str = "/"
    matched_keywords: List[str] = field(default_factory=list)
    ip_address: str = ""
    certificate_info: Dict[str, Any] = field(default_factory=dict)
    request_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


@dataclass
class ScanConfig:
    """Configuration complète d'une session de scan."""
    targets: List[str]
    ports: List[int]
    paths: List[str]
    timeout: int
    threads: int
    use_ssl: bool
    verify_ssl: bool
    follow_redirects: bool
    max_redirects: int
    random_user_agent: bool
    custom_headers: Dict[str, str]
    proxies: List[str]
    proxy_rotation: bool
    output_file: str
    output_format: str
    silent: bool
    verbose: bool
    debug: bool
    filter_status: Optional[List[int]]
    exclude_status: Optional[List[int]]
    min_response_time: Optional[float]
    max_response_time: Optional[float]
    min_content_length: Optional[int]
    max_content_length: Optional[int]
    save_body: bool
    body_dir: str
    method: str = "GET"
    scheme_override: Optional[str] = None
    async_mode: bool = False
    retries: int = 1
    backoff: float = 1.0
    jitter: bool = True
    dns_cache: bool = True
    custom_payload: Optional[str] = None
    cookies: Optional[str] = None
    auth_basic: Optional[str] = None
    auth_bearer: Optional[str] = None
    user_agent_override: Optional[str] = None
    interface: Optional[str] = None
    source_ip: Optional[str] = None
    tcp_pre_check: bool = False
    dry_run: bool = False
    keywords: List[str] = field(default_factory=list)
    exclude_keywords: List[str] = field(default_factory=list)
    regex_filter: Optional[str] = None
    webhook_url: Optional[str] = None
    resolve_ip: bool = False
    full_chain: bool = False


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers réseau & parsing
# ═══════════════════════════════════════════════════════════════════════════════
class NetworkHelpers:
    """Utilitaires réseau génériques."""

    @staticmethod
    def is_valid_hostname_or_ip(value: str) -> bool:
        if not value or len(value) > 253:
            return False
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            pass
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", value):
            return all(0 <= int(part) <= 255 for part in value.split("."))
        allowed = re.compile(r"^[a-zA-Z0-9.-]+$", re.UNICODE)
        return bool(allowed.match(value))

    @staticmethod
    def resolve_hostname(hostname: str) -> Optional[str]:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    @staticmethod
    def get_port_scheme(port: int, prefer_ssl: bool = False) -> str:
        ssl_ports = {443, 8443, 9443}
        plain_ports = {80, 8080, 8000}
        if prefer_ssl:
            return "https"
        if port in ssl_ports:
            return "https"
        if port in plain_ports:
            return "http"
        return "https" if prefer_ssl else "http"

    @staticmethod
    def clean_target(raw: str) -> str:
        raw = raw.strip()
        raw = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
        raw = raw.rstrip("/")
        return raw.split("/")[0]

    @staticmethod
    def parse_url(url: str) -> urllib.parse.ParseResult:
        if not re.match(r"^https?://", url, flags=re.IGNORECASE):
            url = "http://" + url
        return urllib.parse.urlparse(url)

    @staticmethod
    def build_url(host: str, port: int, path: str = "/", scheme: Optional[str] = None) -> str:
        if scheme is None:
            scheme = NetworkHelpers.get_port_scheme(port)
        path = path if path.startswith("/") else "/" + path
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            return f"{scheme}://{host}{path}"
        return f"{scheme}://{host}:{port}{path}"

    @staticmethod
    def extract_title(html_text: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
        if match:
            title = re.sub(r"\s+", " ", match.group(1)).strip()
            return html.unescape(title)
        return ""

    @staticmethod
    def extract_meta_description(html_text: str) -> str:
        match = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', html_text, re.IGNORECASE)
        if match:
            return html.unescape(match.group(1).strip())
        return ""

    @staticmethod
    def extract_technologies(headers: Dict[str, str], body: str) -> List[str]:
        detected: List[str] = []
        combined = " ".join(f"{k}: {v}" for k, v in headers.items()) + " " + body[:8000]
        for tech, signatures in TECH_FINGERPRINTS.items():
            for sig in signatures:
                if sig.lower() in combined.lower():
                    detected.append(tech)
                    break
        return list(sorted(set(detected)))

    @staticmethod
    def parse_status_ranges(text: str) -> List[int]:
        codes: List[int] = []
        if not text:
            return codes
        for part in text.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                codes.extend(range(int(start), int(end) + 1))
            else:
                codes.append(int(part))
        return list(sorted(set(codes)))

    @staticmethod
    def compute_md5(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8", errors="ignore")
        return hashlib.md5(data).hexdigest()

    @staticmethod
    def compute_sha256(data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8", errors="ignore")
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    @staticmethod
    def get_ssl_certificate_info(hostname: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
        info: Dict[str, Any] = {"available": False}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    info["available"] = True
                    info["subject"] = cert.get("subject")
                    info["issuer"] = cert.get("issuer")
                    info["not_after"] = cert.get("notAfter")
                    info["not_before"] = cert.get("notBefore")
                    info["serial_number"] = cert.get("serialNumber")
                    info["version"] = version
                    info["cipher"] = cipher[0] if cipher else ""
                    info["san"] = cert.get("subjectAltName")
        except Exception as exc:
            info["error"] = str(exc)
        return info

    @staticmethod
    def match_keywords(text: str, keywords: List[str]) -> List[str]:
        text_lower = text.lower()
        return [kw for kw in keywords if kw.lower() in text_lower]

    @staticmethod
    def match_regex(text: str, pattern: str) -> List[str]:
        try:
            return re.findall(pattern, text)
        except re.error:
            return []


# ═══════════════════════════════════════════════════════════════════════════════
# Gestion des requêtes HTTP
# ═══════════════════════════════════════════════════════════════════════════════
class RequestEngine:
    """Moteur de requêtes HTTP GET synchrone et asynchrone."""

    def __init__(self, config: ScanConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.lock = threading.Lock()
        self.counter = 0
        self.total = len(config.targets) * len(config.ports) * len(config.paths)
        self.session = self._build_session() if REQUESTS_AVAILABLE else None
        self.dns_cache: Dict[str, str] = {}

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=self.config.retries,
            backoff_factor=self.config.backoff,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            pool_connections=self.config.threads,
            pool_maxsize=self.config.threads * 2,
            max_retries=retry_strategy,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _get_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "DNT": "1",
        }

        if self.config.user_agent_override:
            headers["User-Agent"] = self.config.user_agent_override
        elif self.config.random_user_agent:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        else:
            headers["User-Agent"] = USER_AGENTS[0]

        if self.config.custom_headers:
            headers.update(self.config.custom_headers)

        if self.config.cookies:
            headers["Cookie"] = self.config.cookies

        if self.config.auth_bearer:
            headers["Authorization"] = f"Bearer {self.config.auth_bearer}"
        elif self.config.auth_basic:
            encoded = base64.b64encode(self.config.auth_basic.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        if self.config.custom_payload:
            headers["X-Custom-Payload"] = self.config.custom_payload

        return headers

    def _get_proxy(self) -> Optional[Dict[str, str]]:
        if not self.config.proxies:
            return None
        proxy = random.choice(self.config.proxies) if self.config.proxy_rotation else self.config.proxies[0]
        return {"http": proxy, "https": proxy}

    def _resolve_if_needed(self, host: str) -> str:
        if not self.config.dns_cache:
            return host
        if host not in self.dns_cache:
            resolved = NetworkHelpers.resolve_hostname(host) or host
            self.dns_cache[host] = resolved
        return self.dns_cache[host]

    def _increment_counter(self) -> int:
        with self.lock:
            self.counter += 1
            return self.counter

    def _log_progress(self, current: int, url: str) -> None:
        if self.config.silent:
            return
        percent = (current / self.total) * 100 if self.total else 0
        bar_len = 30
        filled = int(bar_len * current / self.total) if self.total else 0
        bar = "█" * filled + "░" * (bar_len - filled)
        line = f"\r{Colors.CYAN}[{bar}]{Colors.RESET} {current}/{self.total} ({percent:5.1f}%) {Colors.DIM}{url[:60]:<60}{Colors.RESET}"
        sys.stdout.write(line)
        sys.stdout.flush()

    def _build_result(self, target: str, port: int, path: str, url: str, scheme: str, error: str = "") -> ScanResult:
        return ScanResult(
            target=target,
            port=port,
            url=url,
            scheme=scheme,
            path=path,
            error_message=error,
            is_ssl=scheme == "https",
            method=self.config.method,
        )

    def fetch_sync(self, target: str, port: int, path: str) -> ScanResult:
        host = self._resolve_if_needed(target)
        scheme = self.config.scheme_override or NetworkHelpers.get_port_scheme(port, prefer_ssl=self.config.use_ssl)
        url = NetworkHelpers.build_url(host, port, path, scheme)
        proxy = self._get_proxy()
        result = self._build_result(target, port, path, url, scheme)
        result.proxy_used = proxy.get("http", "") if proxy else ""
        result.request_headers = self._get_headers()

        current = self._increment_counter()
        self._log_progress(current, url)

        if self.config.dry_run:
            result.is_alive = True
            result.status_code = 0
            result.error_message = "DRY RUN"
            return result

        if self.config.tcp_pre_check and not NetworkHelpers.is_port_open(host, port, timeout=2.0):
            result.error_message = "TCP port closed"
            return result

        if not REQUESTS_AVAILABLE:
            result.error_message = "Module 'requests' non installé."
            return result

        try:
            start_time = time.perf_counter()
            response = self.session.request(
                method=self.config.method,
                url=url,
                headers=self._get_headers(),
                proxies=proxy,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                allow_redirects=self.config.follow_redirects,
                stream=True,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            content = b""
            try:
                for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                    content += chunk
                    if len(content) > MAX_BODY_STORAGE:
                        break
            except Exception as exc:
                self.logger.debug("Erreur lecture chunk %s: %s", url, exc)

            text = content.decode("utf-8", errors="replace")
            result.is_alive = True
            result.status_code = response.status_code
            result.reason = response.reason
            result.response_time_ms = round(elapsed_ms, 3)
            result.content_length = len(content)
            result.headers = dict(response.headers)
            result.title = NetworkHelpers.extract_title(text)
            result.body_snippet = text[:1024]
            result.technologies = NetworkHelpers.extract_technologies(result.headers, text)
            result.final_url = response.url
            result.redirect_count = len(response.history)
            result.server = response.headers.get("Server", "")
            result.content_type = response.headers.get("Content-Type", "")
            result.hash_md5 = NetworkHelpers.compute_md5(content)
            result.hash_sha256 = NetworkHelpers.compute_sha256(content)
            result.matched_keywords = NetworkHelpers.match_keywords(text, self.config.keywords)
            if self.config.resolve_ip:
                result.ip_address = NetworkHelpers.resolve_hostname(host) or ""
            if self.config.full_chain and scheme == "https":
                result.certificate_info = NetworkHelpers.get_ssl_certificate_info(host, port, self.config.timeout)

        except requests.exceptions.SSLError as exc:
            result.error_message = f"SSL Error: {exc}"
        except requests.exceptions.ConnectionError as exc:
            result.error_message = f"Connection Error: {exc}"
        except requests.exceptions.Timeout:
            result.error_message = "Timeout"
        except requests.exceptions.TooManyRedirects as exc:
            result.error_message = f"Too Many Redirects: {exc}"
        except requests.exceptions.RequestException as exc:
            result.error_message = f"Request Error: {exc}"
        except Exception as exc:
            result.error_message = f"Unexpected Error: {exc}"

        return result

    async def fetch_async(self, target: str, port: int, path: str) -> ScanResult:
        if not AIOHTTP_AVAILABLE:
            return self.fetch_sync(target, port, path)

        host = self._resolve_if_needed(target)
        scheme = self.config.scheme_override or NetworkHelpers.get_port_scheme(port, prefer_ssl=self.config.use_ssl)
        url = NetworkHelpers.build_url(host, port, path, scheme)
        proxy = self._get_proxy()
        result = self._build_result(target, port, path, url, scheme)
        result.proxy_used = proxy.get("http", "") if proxy else ""
        result.request_headers = self._get_headers()

        current = self._increment_counter()
        self._log_progress(current, url)

        if self.config.dry_run:
            result.is_alive = True
            result.status_code = 0
            result.error_message = "DRY RUN"
            return result

        if self.config.tcp_pre_check and not NetworkHelpers.is_port_open(host, port, timeout=2.0):
            result.error_message = "TCP port closed"
            return result

        connector = aiohttp.TCPConnector(
            limit=self.config.threads,
            limit_per_host=self.config.threads,
            ssl=False if not self.config.verify_ssl else None,
        )
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)

        try:
            start_time = time.perf_counter()
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=self._get_headers(),
            ) as session:
                async with session.request(
                    method=self.config.method,
                    url=url,
                    proxy=proxy.get("http") if proxy else None,
                    allow_redirects=self.config.follow_redirects,
                ) as response:
                    content = b""
                    async for chunk in response.content.iter_chunked(CHUNK_SIZE):
                        content += chunk
                        if len(content) > MAX_BODY_STORAGE:
                            break
                    elapsed_ms = (time.perf_counter() - start_time) * 1000
                    text = content.decode("utf-8", errors="replace")
                    result.is_alive = True
                    result.status_code = response.status
                    result.reason = response.reason or ""
                    result.response_time_ms = round(elapsed_ms, 3)
                    result.content_length = len(content)
                    result.headers = dict(response.headers)
                    result.title = NetworkHelpers.extract_title(text)
                    result.body_snippet = text[:1024]
                    result.technologies = NetworkHelpers.extract_technologies(result.headers, text)
                    result.final_url = str(response.url)
                    result.redirect_count = len(response.history)
                    result.server = response.headers.get("Server", "")
                    result.content_type = response.headers.get("Content-Type", "")
                    result.hash_md5 = NetworkHelpers.compute_md5(content)
                    result.hash_sha256 = NetworkHelpers.compute_sha256(content)
                    result.matched_keywords = NetworkHelpers.match_keywords(text, self.config.keywords)
                    if self.config.resolve_ip:
                        result.ip_address = NetworkHelpers.resolve_hostname(host) or ""
                    if self.config.full_chain and scheme == "https":
                        result.certificate_info = NetworkHelpers.get_ssl_certificate_info(host, port, self.config.timeout)

        except aiohttp.ClientSSLError as exc:
            result.error_message = f"SSL Error: {exc}"
        except aiohttp.ClientConnectorError as exc:
            result.error_message = f"Connection Error: {exc}"
        except asyncio.TimeoutError:
            result.error_message = "Timeout"
        except aiohttp.TooManyRedirects as exc:
            result.error_message = f"Too Many Redirects: {exc}"
        except aiohttp.ClientError as exc:
            result.error_message = f"Client Error: {exc}"
        except Exception as exc:
            result.error_message = f"Unexpected Error: {exc}"
        finally:
            connector.close()

        return result


# ═══════════════════════════════════════════════════════════════════════════════
# Filtres & formatage
# ═══════════════════════════════════════════════════════════════════════════════
class ResultFilter:
    """Filtre les résultats selon les critères utilisateur."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def keep(self, result: ScanResult) -> bool:
        if not result.is_alive and self.config.filter_status:
            return False

        if self.config.filter_status and result.status_code not in self.config.filter_status:
            return False
        if self.config.exclude_status and result.status_code in self.config.exclude_status:
            return False

        if self.config.min_response_time is not None and result.response_time_ms < self.config.min_response_time:
            return False
        if self.config.max_response_time is not None and result.response_time_ms > self.config.max_response_time:
            return False

        if self.config.min_content_length is not None and result.content_length < self.config.min_content_length:
            return False
        if self.config.max_content_length is not None and result.content_length > self.config.max_content_length:
            return False

        if self.config.keywords and not result.matched_keywords:
            return False

        if self.config.exclude_keywords:
            body = (result.body_snippet + " " + result.title).lower()
            if any(kw.lower() in body for kw in self.config.exclude_keywords):
                return False

        if self.config.regex_filter:
            if not NetworkHelpers.match_regex(result.body_snippet + result.title, self.config.regex_filter):
                return False

        return True


class ResultFormatter:
    """Formate les résultats pour l'affichage console."""

    @staticmethod
    def colorize_status(code: int) -> str:
        if 200 <= code < 300:
            return f"{Colors.GREEN}{code}{Colors.RESET}"
        if 300 <= code < 400:
            return f"{Colors.YELLOW}{code}{Colors.RESET}"
        if 400 <= code < 500:
            return f"{Colors.MAGENTA}{code}{Colors.RESET}"
        if 500 <= code < 600:
            return f"{Colors.RED}{code}{Colors.RESET}"
        return f"{Colors.WHITE}{code}{Colors.RESET}"

    @staticmethod
    def format_line(result: ScanResult, index: int) -> str:
        status = ResultFormatter.colorize_status(result.status_code)
        title = result.title[:35] if result.title else ""
        tech = ", ".join(result.technologies[:3])
        keywords = ", ".join(result.matched_keywords[:2])
        return (
            f"{Colors.CYAN}[{index:05d}]{Colors.RESET} "
            f"{status:>22} "
            f"{Colors.BLUE}{result.url:<55}{Colors.RESET} "
            f"{Colors.YELLOW}{result.response_time_ms:>8.2f} ms{Colors.RESET} "
            f"{Colors.GREEN}{result.content_length:>10} B{Colors.RESET} "
            f"{Colors.MAGENTA}{title:<38}{Colors.RESET} "
            f"{Colors.ORANGE}{tech:<24}{Colors.RESET} "
            f"{Colors.PINK}{keywords}{Colors.RESET}"
        )

    @staticmethod
    def format_error(result: ScanResult, index: int) -> str:
        return (
            f"{Colors.CYAN}[{index:05d}]{Colors.RESET} "
            f"{Colors.RED}ERROR{Colors.RESET}    "
            f"{Colors.BLUE}{result.url:<55}{Colors.RESET} "
            f"{Colors.DIM}{result.error_message}{Colors.RESET}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Exporteurs
# ═══════════════════════════════════════════════════════════════════════════════
class Exporter:
    """Exporte les résultats vers différents formats."""

    def __init__(self, config: ScanConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger

    def export(self, results: List[ScanResult]) -> None:
        fmt = self.config.output_format.lower()
        path = self.config.output_file
        if not path:
            return

        if fmt == "json":
            self._export_json(results, path)
        elif fmt == "csv":
            self._export_csv(results, path)
        elif fmt == "txt":
            self._export_txt(results, path)
        elif fmt == "html":
            self._export_html(results, path)
        elif fmt == "md":
            self._export_md(results, path)
        elif fmt == "xml":
            self._export_xml(results, path)
        elif fmt == "sqlite":
            self._export_sqlite(results, path)
        else:
            self.logger.warning("Format d'export inconnu: %s", fmt)

    def _export_json(self, results: List[ScanResult], path: str) -> None:
        payload = {
            "metadata": self._metadata(),
            "results": [r.to_dict() for r in results],
            "summary": self._summary(results),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        self.logger.info("Rapport JSON sauvegardé: %s", path)

    def _export_csv(self, results: List[ScanResult], path: str) -> None:
        if not results:
            return
        keys = list(results[0].to_dict().keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for r in results:
                writer.writerow(r.to_dict())
        self.logger.info("Rapport CSV sauvegardé: %s", path)

    def _export_txt(self, results: List[ScanResult], path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self._banner_text())
            for idx, r in enumerate(results, 1):
                f.write(f"\n{'='*80}\n")
                f.write(f"Entry #{idx}\n")
                f.write(f"URL          : {r.url}\n")
                f.write(f"Status       : {r.status_code} {r.reason}\n")
                f.write(f"Time         : {r.response_time_ms} ms\n")
                f.write(f"Size         : {r.content_length} bytes\n")
                f.write(f"Title        : {r.title}\n")
                f.write(f"Technologies : {', '.join(r.technologies)}\n")
                f.write(f"Server       : {r.server}\n")
                f.write(f"Content-Type : {r.content_type}\n")
                f.write(f"Final URL    : {r.final_url}\n")
                f.write(f"IP Address   : {r.ip_address}\n")
                f.write(f"Keywords     : {', '.join(r.matched_keywords)}\n")
                f.write(f"MD5          : {r.hash_md5}\n")
                f.write(f"SHA256       : {r.hash_sha256}\n")
                f.write(f"Error        : {r.error_message}\n")
        self.logger.info("Rapport TXT sauvegardé: %s", path)

    def _export_md(self, results: List[ScanResult], path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write("# HTTP Response Scan Report\n\n")
            f.write(f"**Target:** `{', '.join(self.config.targets)}`\n\n")
            f.write(f"**Ports:** {len(self.config.ports)}\n\n")
            f.write(f"**Paths:** {len(self.config.paths)}\n\n")
            f.write(f"**Generated:** {datetime.datetime.now().isoformat()}\n\n")
            f.write("| # | Port | Status | URL | Time (ms) | Size | Title | Tech | Keywords |\n")
            f.write("|---|------|--------|-----|-----------|------|-------|------|----------|\n")
            for idx, r in enumerate(results, 1):
                f.write(
                    f"| {idx} | {r.port} | {r.status_code} | "
                    f"<{r.url}> | {r.response_time_ms} | {r.content_length} | "
                    f"{r.title} | {', '.join(r.technologies)} | {', '.join(r.matched_keywords)} |\n"
                )
        self.logger.info("Rapport Markdown sauvegardé: %s", path)

    def _export_html(self, results: List[ScanResult], path: str) -> None:
        rows = ""
        for idx, r in enumerate(results, 1):
            status_color = "#2ecc71" if 200 <= r.status_code < 300 else "#e74c3c" if r.status_code >= 400 else "#f1c40f"
            rows += (
                f"<tr>"
                f"<td>{idx}</td>"
                f"<td>{r.port}</td>"
                f"<td style='color:{status_color};font-weight:bold'>{r.status_code}</td>"
                f"<td><a href='{html.escape(r.url)}' target='_blank'>{html.escape(r.url)}</a></td>"
                f"<td>{r.response_time_ms}</td>"
                f"<td>{r.content_length}</td>"
                f"<td>{html.escape(r.title)}</td>"
                f"<td>{', '.join(r.technologies)}</td>"
                f"<td>{html.escape(r.server)}</td>"
                f"<td>{', '.join(r.matched_keywords)}</td>"
                f"<td>{html.escape(r.error_message)}</td>"
                f"</tr>"
            )

        html_doc = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>HTTP Response Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #0f172a; color: #e2e8f0; }}
        h1 {{ color: #38bdf8; }}
        table {{ width: 100%%; border-collapse: collapse; background: #1e293b; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        th, td {{ padding: 12px; border: 1px solid #334155; text-align: left; font-size: 13px; }}
        th {{ background: #0ea5e9; color: #fff; position: sticky; top: 0; }}
        tr:nth-child(even) {{ background: #1e293b; }}
        tr:nth-child(odd) {{ background: #334155; }}
        a {{ color: #38bdf8; text-decoration: none; }}
        .summary {{ margin-bottom: 30px; padding: 15px; background: #1e293b; border-left: 5px solid #0ea5e9; }}
    </style>
</head>
<body>
    <h1>HTTP Response Scan Report</h1>
    <div class="summary">
        <p><strong>Target:</strong> {html.escape(', '.join(self.config.targets))}</p>
        <p><strong>Ports scanned:</strong> {len(self.config.ports)}</p>
        <p><strong>Paths scanned:</strong> {len(self.config.paths)}</p>
        <p><strong>Alive endpoints:</strong> {sum(1 for r in results if r.is_alive)}</p>
        <p><strong>Generated:</strong> {datetime.datetime.now().isoformat()}</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>#</th><th>Port</th><th>Status</th><th>URL</th>
                <th>Time (ms)</th><th>Size</th><th>Title</th><th>Technologies</th><th>Server</th><th>Keywords</th><th>Error</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_doc)
        self.logger.info("Rapport HTML sauvegardé: %s", path)

    def _export_xml(self, results: List[ScanResult], path: str) -> None:
        root = ET.Element("scan")
        meta = ET.SubElement(root, "metadata")
        ET.SubElement(meta, "tool").text = "HTTP Response Advanced Scanner"
        ET.SubElement(meta, "version").text = VERSION
        ET.SubElement(meta, "author").text = AUTHOR
        ET.SubElement(meta, "target").text = ", ".join(self.config.targets)
        ET.SubElement(meta, "generated_at").text = datetime.datetime.now().isoformat()
        results_el = ET.SubElement(root, "results")
        for r in results:
            item = ET.SubElement(results_el, "result")
            for key, value in r.to_dict().items():
                child = ET.SubElement(item, key)
                if isinstance(value, (list, dict)):
                    child.text = json.dumps(value, ensure_ascii=False)
                else:
                    child.text = str(value)
        tree = ET.ElementTree(root)
        tree.write(path, encoding="utf-8", xml_declaration=True)
        self.logger.info("Rapport XML sauvegardé: %s", path)

    def _export_sqlite(self, results: List[ScanResult], path: str) -> None:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                url TEXT,
                scheme TEXT,
                status_code INTEGER,
                reason TEXT,
                response_time_ms REAL,
                content_length INTEGER,
                headers TEXT,
                title TEXT,
                body_snippet TEXT,
                technologies TEXT,
                error_message TEXT,
                timestamp TEXT,
                final_url TEXT,
                redirect_count INTEGER,
                server TEXT,
                content_type TEXT,
                hash_md5 TEXT,
                hash_sha256 TEXT,
                is_alive INTEGER,
                is_ssl INTEGER,
                proxy_used TEXT,
                method TEXT,
                path TEXT,
                matched_keywords TEXT,
                ip_address TEXT
            )
        """)
        for r in results:
            cursor.execute("""
                INSERT INTO results VALUES (
                    NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                r.target, r.port, r.url, r.scheme, r.status_code, r.reason,
                r.response_time_ms, r.content_length, json.dumps(r.headers, ensure_ascii=False),
                r.title, r.body_snippet, ",".join(r.technologies), r.error_message,
                r.timestamp, r.final_url, r.redirect_count, r.server, r.content_type,
                r.hash_md5, r.hash_sha256, int(r.is_alive), int(r.is_ssl), r.proxy_used,
                r.method, r.path, ",".join(r.matched_keywords), r.ip_address,
            ))
        conn.commit()
        conn.close()
        self.logger.info("Base SQLite sauvegardée: %s", path)

    def _metadata(self) -> Dict[str, Any]:
        return {
            "tool": "HTTP Response Advanced Scanner",
            "version": VERSION,
            "author": AUTHOR,
            "targets": self.config.targets,
            "ports": self.config.ports,
            "paths": self.config.paths,
            "timeout": self.config.timeout,
            "threads": self.config.threads,
            "random_user_agent": self.config.random_user_agent,
            "verify_ssl": self.config.verify_ssl,
            "follow_redirects": self.config.follow_redirects,
            "generated_at": datetime.datetime.now().isoformat(),
        }

    def _summary(self, results: List[ScanResult]) -> Dict[str, Any]:
        alive = [r for r in results if r.is_alive]
        status_counts: Dict[int, int] = {}
        for r in alive:
            status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1
        return {
            "total_scanned": len(results),
            "alive": len(alive),
            "errors": len(results) - len(alive),
            "status_distribution": status_counts,
            "average_response_time_ms": round(sum(r.response_time_ms for r in alive) / len(alive), 3) if alive else 0,
            "technologies_found": list(sorted(set(t for r in alive for t in r.technologies))),
        }

    def _banner_text(self) -> str:
        return (
            f"HTTP Response Advanced Scanner v{VERSION} by {AUTHOR}\n"
            f"Targets: {', '.join(self.config.targets)}\n"
            f"Ports: {len(self.config.ports)}\n"
            f"Paths: {len(self.config.paths)}\n"
            f"Date: {datetime.datetime.now().isoformat()}\n"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Notifications webhook
# ═══════════════════════════════════════════════════════════════════════════════
class WebhookNotifier:
    """Envoie un résumé vers une URL webhook."""

    def __init__(self, webhook_url: str, logger: logging.Logger):
        self.webhook_url = webhook_url
        self.logger = logger

    def notify(self, results: List[ScanResult], config: ScanConfig) -> None:
        if not REQUESTS_AVAILABLE:
            self.logger.warning("Module 'requests' manquant pour webhook")
            return
        alive = [r for r in results if r.is_alive]
        payload = {
            "tool": "HTTP Response Advanced Scanner",
            "version": VERSION,
            "author": AUTHOR,
            "target": config.targets,
            "total": len(results),
            "alive": len(alive),
            "errors": len(results) - len(alive),
            "top_results": [r.to_dict() for r in alive[:10]],
        }
        try:
            requests.post(self.webhook_url, json=payload, timeout=10)
            self.logger.info("Notification webhook envoyée")
        except Exception as exc:
            self.logger.warning("Échec webhook: %s", exc)


# ═══════════════════════════════════════════════════════════════════════════════
# Statistiques & rapport console
# ═══════════════════════════════════════════════════════════════════════════════
class StatisticsReporter:
    """Génère un résumé statistique console coloré."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def print_summary(self, results: List[ScanResult], elapsed_total: float) -> None:
        alive = [r for r in results if r.is_alive]
        errors = [r for r in results if not r.is_alive]

        status_counts: Dict[int, int] = {}
        tech_counts: Dict[str, int] = {}
        keyword_counts: Dict[str, int] = {}
        for r in alive:
            status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1
            for tech in r.technologies:
                tech_counts[tech] = tech_counts.get(tech, 0) + 1
            for kw in r.matched_keywords:
                keyword_counts[kw] = keyword_counts.get(kw, 0) + 1

        print(f"\n\n{Colors.BOLD}{'═'*90}{Colors.RESET}")
        print(f"{Colors.BOLD}{' '*30}RESPONSE SCAN SUMMARY{' '*35}{Colors.RESET}")
        print(f"{Colors.BOLD}{'═'*90}{Colors.RESET}")
        print(f"  {Colors.CYAN}Targets             :{Colors.RESET} {', '.join(self.config.targets)}")
        print(f"  {Colors.CYAN}Ports scanned       :{Colors.RESET} {len(self.config.ports)}")
        print(f"  {Colors.CYAN}Paths scanned       :{Colors.RESET} {len(self.config.paths)}")
        print(f"  {Colors.CYAN}Total requests      :{Colors.RESET} {len(results)}")
        print(f"  {Colors.CYAN}Alive endpoints     :{Colors.RESET} {len(alive)}")
        print(f"  {Colors.CYAN}Errors / timeouts   :{Colors.RESET} {len(errors)}")
        print(f"  {Colors.CYAN}Total duration      :{Colors.RESET} {elapsed_total:.3f} s")
        print(f"  {Colors.CYAN}Req/sec             :{Colors.RESET} {len(results)/elapsed_total:.2f}")
        print(f"{Colors.BOLD}{'─'*90}{Colors.RESET}")
        print(f"  {Colors.BOLD}Status distribution:{Colors.RESET}")
        for code in sorted(status_counts.keys()):
            color = Colors.GREEN if 200 <= code < 300 else Colors.YELLOW if 300 <= code < 400 else Colors.RED
            print(f"    {color}{code}{Colors.RESET}: {status_counts[code]}")
        print(f"{Colors.BOLD}{'─'*90}{Colors.RESET}")
        print(f"  {Colors.BOLD}Technologies detected:{Colors.RESET}")
        for tech, count in sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
            print(f"    {Colors.MAGENTA}{tech}{Colors.RESET}: {count}")
        if keyword_counts:
            print(f"{Colors.BOLD}{'─'*90}{Colors.RESET}")
            print(f"  {Colors.BOLD}Keywords matched:{Colors.RESET}")
            for kw, count in sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
                print(f"    {Colors.PINK}{kw}{Colors.RESET}: {count}")
        print(f"{Colors.BOLD}{'═'*90}{Colors.RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Orchestrateur de scan
# ═══════════════════════════════════════════════════════════════════════════════
class ScannerOrchestrator:
    """Coordonne le scan complet (synchrone ou asynchrone)."""

    def __init__(self, config: ScanConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.engine = RequestEngine(config, logger)
        self.filter = ResultFilter(config)
        self.formatter = ResultFormatter()
        self.exporter = Exporter(config, logger)
        self.reporter = StatisticsReporter(config)
        self.webhook = WebhookNotifier(config.webhook_url, logger) if config.webhook_url else None
        self.results: List[ScanResult] = []
        self.filtered_results: List[ScanResult] = []

    def _generate_tasks(self) -> List[Tuple[str, int, str]]:
        tasks: List[Tuple[str, int, str]] = []
        for target in self.config.targets:
            for port in self.config.ports:
                for path in self.config.paths:
                    tasks.append((target, port, path))
        return tasks

    def run_sync(self) -> List[ScanResult]:
        tasks = self._generate_tasks()
        self.logger.info("Démarrage du scan synchrone sur %s tâches", len(tasks))
        q: queue.Queue[ScanResult] = queue.Queue()

        def worker(task_chunk: Iterable[Tuple[str, int, str]]) -> None:
            for target, port, path in task_chunk:
                try:
                    result = self.engine.fetch_sync(target, port, path)
                    q.put(result)
                except Exception as exc:
                    self.logger.error("Exception worker %s:%s%s: %s", target, port, path, exc)

        threads: List[threading.Thread] = []
        tasks_per_thread = max(1, len(tasks) // self.config.threads)
        task_chunks = [
            tasks[i:i + tasks_per_thread]
            for i in range(0, len(tasks), tasks_per_thread)
        ]

        start_time = time.perf_counter()
        for chunk in task_chunks:
            t = threading.Thread(target=worker, args=(chunk,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        while not q.empty():
            self.results.append(q.get())

        self.results.sort(key=lambda r: (r.target, r.port, r.path))
        self._post_process(start_time)
        return self.filtered_results

    async def run_async(self) -> List[ScanResult]:
        tasks = self._generate_tasks()
        self.logger.info("Démarrage du scan asynchrone sur %s tâches", len(tasks))
        semaphore = asyncio.Semaphore(self.config.threads)

        async def bounded_fetch(target: str, port: int, path: str) -> ScanResult:
            async with semaphore:
                if self.config.jitter:
                    await asyncio.sleep(random.uniform(0, 0.05))
                return await self.engine.fetch_async(target, port, path)

        start_time = time.perf_counter()
        coros = [bounded_fetch(t, p, pa) for t, p, pa in tasks]
        self.results = await asyncio.gather(*coros, return_exceptions=True)

        processed: List[ScanResult] = []
        for item in self.results:
            if isinstance(item, Exception):
                self.logger.error("Exception asynchrone: %s", item)
            else:
                processed.append(item)
        self.results = sorted(processed, key=lambda r: (r.target, r.port, r.path))

        self._post_process(start_time)
        return self.filtered_results

    def _post_process(self, start_time: float) -> None:
        elapsed_total = time.perf_counter() - start_time
        self.filtered_results = [r for r in self.results if self.filter.keep(r)]

        if not self.config.silent:
            print("\n")
            print(f"{Colors.BOLD}{'═'*140}{Colors.RESET}")
            print(f"{Colors.BOLD}{' '*50}RESPONSE RESULTS{' '*72}{Colors.RESET}")
            print(f"{Colors.BOLD}{'═'*140}{Colors.RESET}")
            for idx, r in enumerate(self.filtered_results, 1):
                if r.is_alive:
                    print(self.formatter.format_line(r, idx))
                else:
                    if self.config.verbose:
                        print(self.formatter.format_error(r, idx))

        self.reporter.print_summary(self.results, elapsed_total)

        if self.config.save_body:
            self._save_bodies()

        self.exporter.export(self.filtered_results)

        if self.webhook:
            self.webhook.notify(self.filtered_results, self.config)

        if not self.config.silent:
            print(f"\n{Colors.GREEN}Scan terminé.{Colors.RESET} Résultats filtrés: {len(self.filtered_results)}/{len(self.results)}")

    def _save_bodies(self) -> None:
        body_dir = Path(self.config.body_dir)
        body_dir.mkdir(parents=True, exist_ok=True)
        for r in self.filtered_results:
            if r.is_alive and r.body_snippet:
                safe_name = re.sub(r"[^\w\-_.]", "_", f"{r.target}_{r.port}_{r.path.replace('/', '_')}_{r.status_code}")
                file_path = body_dir / f"{safe_name}.txt"
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(r.body_snippet)
                except Exception as exc:
                    self.logger.warning("Impossible de sauvegarder le body pour %s: %s", r.url, exc)


# ═══════════════════════════════════════════════════════════════════════════════
# Parsing des arguments CLI
# ═══════════════════════════════════════════════════════════════════════════════
def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="http_response_scanner.py",
        description="Advanced HTTP Response Scanner - URL-First Multi-Endpoint GET Engine by hackers_tchad",
        epilog="Exemple: python http_response_scanner.py -t example.com -p 80,443,8080 -T 100 -o result.json",
    )

    parser.add_argument("-t", "--target", action="append", default=[], help="Hôte cible (domaine ou IP). Répétable.")
    parser.add_argument("-u", "--url", action="append", default=[], help="URL complète. Répétable.")
    parser.add_argument("-f", "--target-file", help="Fichier contenant une cible ou URL par ligne")
    parser.add_argument(
        "-p", "--ports",
        default=",".join(map(str, DEFAULT_PORTS)),
        help="Ports à scanner: liste séparée par virgules ou 'top100'/'web'/'all'",
    )
    parser.add_argument("--paths", default="/", help="Chemins à scanner séparés par virgules (défaut: /)")
    parser.add_argument("--path-file", help="Fichier de chemins (un par ligne)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout par requête (secondes)")
    parser.add_argument("-T", "--threads", type=int, default=DEFAULT_THREADS, help="Nombre de threads/concurrences")
    parser.add_argument("--ssl", action="store_true", help="Préférer HTTPS sur les ports non standards")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Désactiver la vérification SSL")
    parser.add_argument("--no-follow-redirects", action="store_true", help="Ne pas suivre les redirections")
    parser.add_argument("--max-redirects", type=int, default=MAX_REDIRECTS, help="Nombre max de redirections")
    parser.add_argument("--random-user-agent", action="store_true", help="Rotation aléatoire des User-Agents")
    parser.add_argument("--user-agent", help="User-Agent personnalisé")
    parser.add_argument("-H", "--headers", action="append", default=[], help="Header personnalisé 'Key: Value'")
    parser.add_argument("--proxy", action="append", default=[], help="Proxy (http://host:port ou socks5://host:port)")
    parser.add_argument("--proxy-rotate", action="store_true", help="Rotation aléatoire des proxies")
    parser.add_argument("-o", "--output", help="Fichier de sortie")
    parser.add_argument("--format", default="json", choices=["json", "csv", "txt", "html", "md", "xml", "sqlite"], help="Format de sortie")
    parser.add_argument("-s", "--silent", action="store_true", help="Mode silencieux (logs dans scanner.log)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mode verbeux")
    parser.add_argument("-d", "--debug", action="store_true", help="Mode debug")
    parser.add_argument("--filter-status", help="Filtrer les status (ex: 200,301,302 ou 200-299)")
    parser.add_argument("--exclude-status", help="Exclure les status (ex: 404,500)")
    parser.add_argument("--min-time", type=float, help="Temps de réponse minimum (ms)")
    parser.add_argument("--max-time", type=float, help="Temps de réponse maximum (ms)")
    parser.add_argument("--min-size", type=int, help="Taille minimum du contenu (bytes)")
    parser.add_argument("--max-size", type=int, help="Taille maximum du contenu (bytes)")
    parser.add_argument("--save-body", action="store_true", help="Sauvegarder les corps de réponse")
    parser.add_argument("--body-dir", default="./bodies", help="Répertoire de sauvegarde des corps")
    parser.add_argument("--async", dest="async_mode", action="store_true", help="Utiliser le mode asynchrone (aiohttp)")
    parser.add_argument("--retries", type=int, default=1, help="Nombre de tentatives par requête")
    parser.add_argument("--backoff", type=float, default=1.0, help="Facteur de backoff exponentiel")
    parser.add_argument("--no-jitter", action="store_true", help="Désactiver le jitter en mode async")
    parser.add_argument("--no-dns-cache", action="store_true", help="Désactiver le cache DNS")
    parser.add_argument("--cookies", help="Cookies à envoyer (format: a=1;b=2)")
    parser.add_argument("--auth-basic", help="Authentification Basic (user:pass)")
    parser.add_argument("--auth-bearer", help="Token Bearer")
    parser.add_argument("--scheme", choices=["http", "https"], help="Forcer le schéma http ou https")
    parser.add_argument("--source-ip", help="IP source à binder (si supporté)")
    parser.add_argument("--tcp-pre-check", action="store_true", help="Vérifier si le port TCP est ouvert avant requête")
    parser.add_argument("--dry-run", action="store_true", help="Générer les URLs sans envoyer de requêtes")
    parser.add_argument("--keyword", action="append", default=[], help="Mot-clé à rechercher dans le body. Répétable.")
    parser.add_argument("--exclude-keyword", action="append", default=[], help="Mot-clé excluant. Répétable.")
    parser.add_argument("--regex", help="Regex à rechercher dans le body/title")
    parser.add_argument("--resolve-ip", action="store_true", help="Résoudre l'IP de chaque cible")
    parser.add_argument("--full-chain", action="store_true", help="Récupérer les informations du certificat SSL")
    parser.add_argument("--webhook", help="URL webhook pour notification de fin de scan")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    return parser


def parse_ports(value: str) -> List[int]:
    value = value.lower().strip()
    if value in ("top100", "web"):
        return COMMON_WEB_PORTS[:100]
    if value == "all":
        return COMMON_WEB_PORTS
    ports: List[int] = []
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return list(sorted(set(ports)))


def parse_paths(value: str) -> List[str]:
    paths = []
    for part in value.split(","):
        p = part.strip()
        if not p.startswith("/"):
            p = "/" + p
        paths.append(p)
    return paths or ["/"]


def parse_headers(raw_headers: List[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for h in raw_headers:
        if ":" not in h:
            continue
        key, val = h.split(":", 1)
        headers[key.strip()] = val.strip()
    return headers


def load_lines(path: str) -> List[str]:
    if not path or not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


def extract_targets_from_urls(urls: List[str]) -> List[str]:
    targets: List[str] = []
    for url in urls:
        parsed = NetworkHelpers.parse_url(url)
        host = parsed.hostname
        if host:
            targets.append(host)
    return targets


def build_config_from_args(args: argparse.Namespace) -> ScanConfig:
    targets: List[str] = []
    if args.target:
        targets.extend(args.target)
    if args.url:
        targets.extend(extract_targets_from_urls(args.url))
    if args.target_file:
        lines = load_lines(args.target_file)
        for line in lines:
            if re.match(r"^https?://", line, flags=re.IGNORECASE):
                targets.extend(extract_targets_from_urls([line]))
            else:
                targets.append(line)

    targets = [NetworkHelpers.clean_target(t) for t in targets]
    targets = list(dict.fromkeys(t for t in targets if t))

    ports = parse_ports(args.ports)
    paths = parse_paths(args.paths)
    if args.path_file:
        paths.extend(load_lines(args.path_file))
        paths = list(dict.fromkeys(paths))

    custom_headers = parse_headers(args.headers)

    output_file = args.output or f"scan_report.{args.format}"

    return ScanConfig(
        targets=targets,
        ports=ports,
        paths=paths,
        timeout=args.timeout,
        threads=args.threads,
        use_ssl=args.ssl,
        verify_ssl=not args.no_verify_ssl,
        follow_redirects=not args.no_follow_redirects,
        max_redirects=args.max_redirects,
        random_user_agent=args.random_user_agent,
        custom_headers=custom_headers,
        proxies=args.proxy,
        proxy_rotation=args.proxy_rotate,
        output_file=output_file,
        output_format=args.format,
        silent=args.silent,
        verbose=args.verbose,
        debug=args.debug,
        filter_status=NetworkHelpers.parse_status_ranges(args.filter_status) if args.filter_status else None,
        exclude_status=NetworkHelpers.parse_status_ranges(args.exclude_status) if args.exclude_status else None,
        min_response_time=args.min_time,
        max_response_time=args.max_time,
        min_content_length=args.min_size,
        max_content_length=args.max_size,
        save_body=args.save_body,
        body_dir=args.body_dir,
        async_mode=args.async_mode,
        retries=args.retries,
        backoff=args.backoff,
        jitter=not args.no_jitter,
        dns_cache=not args.no_dns_cache,
        cookies=args.cookies,
        auth_basic=args.auth_basic,
        auth_bearer=args.auth_bearer,
        user_agent_override=args.user_agent,
        source_ip=args.source_ip,
        tcp_pre_check=args.tcp_pre_check,
        dry_run=args.dry_run,
        keywords=args.keyword,
        exclude_keywords=args.exclude_keyword,
        regex_filter=args.regex,
        webhook_url=args.webhook,
        resolve_ip=args.resolve_ip,
        full_chain=args.full_chain,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════════════════════════════════════════
def setup_logger(config: ScanConfig) -> logging.Logger:
    logger = logging.getLogger("http_response_scanner")
    logger.handlers.clear()

    if config.debug:
        level = logging.DEBUG
    elif config.verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logger.setLevel(level)

    if config.silent:
        handler = logging.FileHandler("scanner.log", mode="w")
    else:
        handler = logging.StreamHandler(sys.stdout)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


# ═══════════════════════════════════════════════════════════════════════════════
# Validation prévol
# ═══════════════════════════════════════════════════════════════════════════════
def validate_environment(config: ScanConfig, logger: logging.Logger) -> bool:
    if not config.targets:
        logger.error("Aucune cible fournie. Utilisez -t, -u ou -f.")
        return False

    for target in config.targets:
        if not NetworkHelpers.is_valid_hostname_or_ip(target):
            logger.error("Cible invalide: %s", target)
            return False

    if config.async_mode and not AIOHTTP_AVAILABLE:
        logger.warning("aiohttp non installé, retour au mode synchrone.")
        config.async_mode = False

    if not REQUESTS_AVAILABLE and not config.async_mode:
        logger.error("Module 'requests' requis en mode synchrone. Installez-le: pip install requests")
        return False

    if config.threads < 1:
        logger.error("Le nombre de threads doit être >= 1")
        return False

    if not config.ports:
        logger.error("Aucun port à scanner")
        return False

    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Point d'entrée principal
# ═══════════════════════════════════════════════════════════════════════════════
def main() -> int:
    parser = create_argument_parser()
    args = parser.parse_args()

    config = build_config_from_args(args)
    logger = setup_logger(config)

    if not COLORAMA_AVAILABLE:
        Colors.disable()

    if not config.silent:
        print(Colors.CYAN + BANNER + Colors.RESET)

    logger.info("Auteur: %s | Cibles: %s | Ports: %d | Threads: %d | Mode: %s",
                AUTHOR, config.targets, len(config.ports), config.threads,
                "async" if config.async_mode else "sync")

    if not validate_environment(config, logger):
        return 1

    orchestrator = ScannerOrchestrator(config, logger)

    try:
        if config.async_mode:
            results = asyncio.run(orchestrator.run_async())
        else:
            results = orchestrator.run_sync()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interruption utilisateur.{Colors.RESET}")
        return 130
    except Exception as exc:
        logger.exception("Erreur fatale durant le scan: %s", exc)
        return 1

    logger.info("Scan terminé avec %d résultat(s) filtré(s).", len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
