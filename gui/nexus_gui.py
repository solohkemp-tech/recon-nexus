#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON//NEXUS v3.0.0 — GUI EDITION
Smart Pentest Recon Engine · zero-dependency (Python stdlib + Tkinter only)
No API keys · Passive OSINT + Active recon · Live telemetry · Reporting

Run:  python nexus_gui.py

by empsolohk
"""
import json, math, os, queue, random, re, socket, ssl, sys, threading, time, webbrowser
import urllib.request, urllib.error, urllib.parse
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "3.0.0"

# ═══════════════════════════ PALETTE ═══════════════════════════
COL = dict(bg0='#070c14', bg1='#0a1120', panel='#0c1424', panel2='#101a2e',
           line='#182741', line2='#243a61', txt='#c7d5ee', dim='#5c7195',
           bright='#eef4ff', grn='#2ee6a8', cyn='#45c8ff', amb='#ffb545',
           red='#ff5470', mag='#c77dff', blu='#6ea8ff', sel='#123a52')
SEVC = {'critical': '#ff5470', 'high': '#ffb545', 'medium': '#45c8ff',
        'low': '#2ee6a8', 'info': '#6ea8ff'}
SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
LOGC = {'sys': '#c77dff', 'info': '#45c8ff', 'ok': '#2ee6a8',
        'warn': '#ffb545', 'err': '#ff5470', 'ts': '#5c7195'}

# ═══════════════════════════ NETWORK CORE ═══════════════════════════
DEFAULT_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/126.0 Safari/537.36')
DOMAIN_RE = re.compile(r'^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$', re.I)

def normalize_domain(t):
    t = t.strip().lower()
    t = re.sub(r'^https?://', '', t)
    return t.split('/')[0].split(':')[0]

def http_request(url, cfg, max_read=65536, headers=None, timeout=None):
    handlers = []
    if cfg.get('proxy'):
        handlers.append(urllib.request.ProxyHandler({'http': cfg['proxy'], 'https': cfg['proxy']}))
    if cfg.get('ctx'):
        handlers.append(urllib.request.HTTPSHandler(context=cfg['ctx']))
    opener = urllib.request.build_opener(*handlers)
    base = {'User-Agent': cfg.get('ua', DEFAULT_UA), 'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9', 'Connection': 'close'}
    if headers: base = {**base, **headers}
    req = urllib.request.Request(url, headers=base)
    try:
        resp = opener.open(req, timeout=timeout or cfg.get('timeout', 10))
        body = resp.read(max_read)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body, resp.geturl()
    except urllib.error.HTTPError as e:
        body = b''
        try: body = e.read(max_read)
        except Exception: pass
        return e.code, {k.lower(): v for k, v in e.headers.items()}, body, url
    except Exception as e:
        return None, {}, b'', str(e)

DOH_SERVERS = [
    ('https://cloudflare-dns.com/dns-query?name={n}&type={t}', {'Accept': 'application/dns-json'}),
    ('https://dns.google/resolve?name={n}&type={t}', {}),
    ('https://dns.quad9.net:5053/dns-query?name={n}&type={t}', {'Accept': 'application/dns-json'}),
]

def doh(name, rtype, cfg):
    """DNS-over-HTTPS — keyless · multi-resolver · native fallback."""
    for tmpl, hdrs in DOH_SERVERS:
        url = tmpl.format(n=urllib.parse.quote(name), t=rtype)
        s, _, b, _ = http_request(url, cfg, headers=hdrs, timeout=6)
        if s == 200:
            try:
                j = json.loads(b)
                if j.get('Status', 0) in (0, 3):
                    return [a.get('data', '') for a in j.get('Answer', [])]
            except Exception:
                continue
    if rtype in ('A', 'AAAA'):
        try:
            fam = socket.AF_INET if rtype == 'A' else socket.AF_INET6
            return sorted({i[4][0] for i in socket.getaddrinfo(name, None, fam, socket.SOCK_STREAM)})
        except Exception:
            pass
    return []
def hb(n):
    n = float(n)
    for u in ('B', 'KB', 'MB', 'GB'):
        if n < 1024: return f"{n:.0f}{u}" if u == 'B' else f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}TB"

# ═══════════════════════════ DORK ARSENAL ═══════════════════════════
# (label, query/{t} or direct url, severity, is_direct)
DORKS = [
 ("FILE & DIRECTORY DISCOVERY", [
  ("Directory listing", 'intitle:"index of /" site:{t}', "high", False),
  ("Exposed config files", 'site:{t} ext:cfg OR ext:conf OR ext:ini OR ext:config', "high", False),
  ("Exposed database files", 'site:{t} ext:sql OR ext:db OR ext:dbf OR ext:mdb', "critical", False),
  ("Exposed log files", 'site:{t} ext:log', "medium", False),
  ("Backup & old files", 'site:{t} ext:bak OR ext:backup OR ext:old OR ext:orig OR ext:zip OR ext:tar.gz', "high", False),
  ("Public documents", 'site:{t} ext:doc OR ext:docx OR ext:pdf OR ext:xlsx', "low", False),
  ("Config PHP files", 'site:{t} ext:php intitle:"config"', "high", False),
  ("Admin backup archives", 'inurl:admin site:{t} ext:zip OR ext:sql OR ext:bak', "critical", False),
  ("WordPress config", 'site:{t} inurl:wp-config', "critical", False),
  ("WordPress backups", 'site:{t} inurl:wp-content intitle:"index of" backup', "high", False),
  ("MySQL config", 'site:{t} ext:cnf mysql', "high", False),
  ("Exposed .git", 'site:{t} inurl:".git"', "critical", False),
  ("Exposed .env", 'site:{t} ext:env', "critical", False),
  ("Exposed .DS_Store", 'site:{t} inurl:".DS_Store"', "medium", False),
  ("Private key files", 'site:{t} ext:pem OR ext:key OR ext:ppk "PRIVATE KEY"', "critical", False),
  ("SSH id_rsa", 'site:{t} intitle:"index of" "id_rsa"', "critical", False),
  ("Password / shadow", 'site:{t} intitle:"index of" passwd OR passwords.txt OR shadow', "critical", False)]),
 ("WEB APPLICATION DISCOVERY", [
  ("Login pages", 'site:{t} inurl:login OR inurl:signin OR inurl:wp-login', "info", False),
  ("SQL error leakage", 'site:{t} "SQL syntax" OR "MySQL server version" OR "ORA-01756"', "high", False),
  ("phpinfo()", 'site:{t} intitle:"phpinfo()"', "high", False),
  ("Backdoor shells", 'site:{t} inurl:shell.php OR inurl:c99 OR inurl:r57 OR inurl:b374k', "critical", False),
  ("Install / setup", 'site:{t} inurl:install.php OR inurl:setup.php OR inurl:upgrade.php', "medium", False),
  ("Open redirects", 'site:{t} inurl:redirect= OR inurl:return= OR inurl:next= OR inurl:url=', "medium", False),
  ("Struts RCE surface", 'site:{t} ext:action OR ext:do', "medium", False),
  ("Admin portals", 'site:{t} inurl:admin OR inurl:administrator OR inurl:dashboard', "info", False),
  ("Upload pages", 'site:{t} inurl:upload.php OR inurl:uploader', "high", False),
  ("Drupal logins", 'site:{t} inurl:user/login', "info", False),
  ("Joomla config", 'site:{t} inurl:configuration.php', "high", False),
  ("Debug / stack traces", 'site:{t} "stack trace" OR "fatal error" OR intitle:"Server Error"', "medium", False),
  ("phpMyAdmin", 'site:{t} intitle:"phpMyAdmin"', "high", False),
  ("Test / staging / dev", 'site:{t} inurl:test OR inurl:staging OR inurl:dev.', "low", False)]),
 ("INFORMATION GATHERING", [
  ("Pastebin entries", 'site:pastebin.com "{t}"', "high", False),
  ("LinkedIn employees", 'site:linkedin.com/in "{t}"', "low", False),
  ("Sensitive text files", 'site:{t} ext:txt password OR secret OR token', "high", False),
  ("Subdomains", 'site:*.{t}', "medium", False),
  ("Sub-subdomains", 'site:*.*.{t}', "medium", False),
  ("Certificate transparency", 'https://crt.sh/?q=%25.{t}', "info", True),
  ("Reddit mentions", 'site:reddit.com "{t}"', "low", False),
  ("GitHub mentions", 'site:github.com "{t}"', "medium", False),
  ("Trello boards", 'site:trello.com "{t}"', "medium", False),
  ("Email harvest", 'site:{t} "@{t}"', "medium", False),
  ("S3 mentions", 'site:s3.amazonaws.com "{t}"', "medium", False),
  ("HackerNews mentions", '"{t}" site:news.ycombinator.com', "low", False)]),
 ("CLOUD & INFRASTRUCTURE", [
  ("HackerOne reports", 'site:hackerone.com "{t}"', "info", False),
  ("Bugcrowd reports", 'site:bugcrowd.com "{t}"', "info", False),
  ("Censys search", 'https://search.censys.io/search?query={t}', "info", True),
  ("Shodan search", 'https://www.shodan.io/search?query={t}', "info", True),
  ("Jenkins", 'site:{t} intitle:"Dashboard [Jenkins]"', "high", False),
  ("Kibana", 'site:{t} intitle:"Kibana"', "high", False),
  ("AWS S3 buckets", 'site:{t}.s3.amazonaws.com', "high", False),
  ("Kubernetes dashboard", 'site:{t} intitle:"Kubernetes Dashboard"', "critical", False),
  ("Exposed Docker API", 'site:{t} inurl:":2375"', "critical", False),
  ("Firebase", 'site:{t} inurl:firebaseio.com', "high", False),
  ("MongoDB", 'site:{t} inurl:":27017"', "critical", False),
  ("Jupyter notebooks", 'site:{t} intitle:"Jupyter Notebook"', "high", False),
  ("Grafana", 'site:{t} intitle:"Grafana"', "medium", False),
  ("Elasticsearch", 'site:{t} inurl:":9200"', "high", False),
  ("SonarQube", 'site:{t} intitle:"SonarQube"', "high", False),
  ("Apache Airflow", 'site:{t} intitle:"Airflow - DAGs"', "high", False),
  ("RabbitMQ mgmt", 'site:{t} intitle:"RabbitMQ Management"', "medium", False)]),
 ("API & DEVELOPMENT", [
  ("GitHub secrets", 'site:github.com "{t}" password OR secret OR api_key OR token', "critical", False),
  ("Flash files", 'site:{t} ext:swf', "low", False),
  ("GeoServer WFS", 'site:{t} inurl:geoserver', "medium", False),
  ("ArcGIS", 'site:{t} inurl:arcgis', "medium", False),
  ("Ansible playbooks", 'site:{t} ext:yml "hosts:" OR "ansible"', "medium", False),
  ("API info pages", 'site:{t} inurl:"/api/"', "info", False),
  ("SQL query in URL", 'site:{t} inurl:.php?id=', "high", False),
  ("JSON-RPC", 'site:{t} inurl:jsonrpc OR inurl:"json-rpc"', "medium", False),
  ("JWKS-RSA", 'site:{t} inurl:jwks.json', "medium", False),
  ("YAML with secrets", 'site:{t} ext:yaml OR ext:yml password OR secret', "high", False),
  ("Docker compose", 'site:{t} "docker-compose.yml"', "medium", False),
  ("GraphQL endpoints", 'site:{t} inurl:graphql', "high", False),
  ("API keys & secrets", 'site:{t} "api_key" OR "apikey" OR "secret_key" OR "access_token"', "critical", False),
  ("JIRA dashboards", 'site:{t} inurl:jira OR site:{t}.atlassian.net', "medium", False),
  ("Spring actuator", 'site:{t} inurl:actuator', "high", False),
  ("Actuator /env dump", 'site:{t} inurl:actuator/env', "critical", False),
  ("Prometheus", 'site:{t} intitle:"Prometheus Time Series"', "medium", False),
  ("Env with secrets", 'site:{t} ext:env DB_PASSWORD OR API_KEY OR SECRET', "critical", False),
  ("Swagger / api-docs", 'site:{t} inurl:swagger OR inurl:api-docs', "medium", False),
  ("Confluence / wiki", 'site:{t} inurl:confluence OR inurl:"atlassian.net/wiki"', "medium", False),
  ("Postman collections", 'site:getpostman.com "{t}"', "medium", False),
  ("npm traces", 'site:npmjs.com "{t}"', "low", False)]),
 ("MODERN PLATFORMS & CI/CD", [
  ("n8n automation", 'site:{t} intitle:"n8n"', "high", False),
  ("Ray dashboard", 'site:{t} intitle:"Ray Dashboard"', "critical", False),
  ("Apache Superset", 'site:{t} intitle:"Superset"', "high", False),
  ("MinIO console", 'site:{t} intitle:"MinIO Console"', "high", False),
  ("Argo CD", 'site:{t} intitle:"Argo CD"', "high", False),
  ("Portainer", 'site:{t} intitle:"Portainer"', "high", False),
  ("Rancher", 'site:{t} intitle:"Rancher"', "high", False),
  ("Keycloak SSO", 'site:{t} inurl:keycloak', "high", False),
  ("Gitea", 'site:{t} intitle:"Gitea"', "medium", False),
  ("Backstage portal", 'site:{t} intitle:"Backstage"', "medium", False),
  ("Weave Scope", 'site:{t} intitle:"Weave Scope"', "critical", False),
  ("Consul UI", 'site:{t} intitle:"Consul"', "high", False),
  ("K8s API anonymous", 'site:{t} inurl:"/api/v1/namespaces"', "critical", False),
  ("Kong Manager", 'site:{t} intitle:"Kong Manager"', "high", False),
  ("Flink dashboard", 'site:{t} intitle:"Flink Dashboard"', "high", False),
  ("Spark master", 'site:{t} intitle:"Spark Master Cluster"', "high", False),
  ("phpRedisAdmin", 'site:{t} intitle:"phpRedisAdmin"', "high", False),
  ("Mongo Express", 'site:{t} intitle:"Mongo Express"', "critical", False),
  ("Adminer", 'site:{t} intitle:"Adminer"', "high", False),
  ("Laravel Ignition", 'site:{t} inurl:"_ignition/health-check"', "critical", False),
  ("Laravel Telescope", 'site:{t} inurl:telescope', "high", False),
  ("Solr admin", 'site:{t} inurl:"/solr/"', "high", False),
  ("Nexus Repository", 'site:{t} intitle:"Nexus Repository"', "high", False),
  ("VMware vCenter", 'site:{t} intitle:"vCenter"', "critical", False),
  ("Proxmox", 'site:{t} intitle:"Proxmox"', "high", False),
  ("Zabbix", 'site:{t} intitle:"Zabbix"', "high", False),
  ("Uptime Kuma", 'site:{t} intitle:"Uptime Kuma"', "low", False)]),
 ("ARCHIVES & HISTORICAL", [
  ("crossdomain.xml", 'site:{t} inurl:crossdomain.xml', "medium", False),
  ("ThreatCrowd intel", 'https://www.threatcrowd.org/domain.php?domain={t}', "info", True),
  ("Archive.org SWF", 'site:web.archive.org "{t}" ext:swf', "low", False),
  ("Archive.org history", 'https://web.archive.org/web/*/{t}', "info", True),
  ("Archive.org full site", 'https://web.archive.org/web/*.{t}', "info", True),
  ("Archive.org WP files", 'site:web.archive.org "{t}" wp-content', "low", False),
  ("Direct downloads", 'site:{t} ext:apk OR ext:exe OR ext:msi OR ext:ipa', "medium", False),
  ("Exposed /etc", 'site:{t} inurl:"/etc/"', "high", False),
  ("SQL directories", 'site:{t} inurl:"/sql/" OR inurl:"/db/"', "high", False),
  ("VirusTotal", 'https://www.virustotal.com/gui/domain/{t}', "info", True),
  ("SecurityTrails", 'https://securitytrails.com/domain/{t}/dns', "info", True),
  ("urlscan.io", 'https://urlscan.io/domain/{t}', "info", True),
  ("Wayback CDX index", 'https://web.archive.org/cdx/search/cdx?url=*.{t}*&output=text&fl=original&collapse=urlkey', "medium", True)]),
]
N_DORKS = sum(len(d[1]) for d in DORKS)

ENGINES = {
    'GOOGLE': 'https://www.google.com/search?q={}',
    'BING': 'https://www.bing.com/search?q={}',
    'DUCKDUCKGO': 'https://duckduckgo.com/?q={}',
    'YANDEX': 'https://yandex.com/search/?text={}',
    'STARTPAGE': 'https://www.startpage.com/sp/search?query={}',
}

# ═══════════════════════════ ACTIVE PROBES ═══════════════════════════
PROBES = [
 ("/.git/config","critical","Git repository exposed"),("/.git/HEAD","critical","Git HEAD reference"),
 ("/.env","critical","Environment secrets"),("/.env.local","critical","Local env secrets"),
 ("/.env.production","critical","Production env secrets"),("/.aws/credentials","critical","AWS credentials"),
 ("/.ssh/authorized_keys","critical","SSH keys"),("/.bash_history","critical","Shell history"),
 ("/id_rsa","critical","Private key"),("/server.key","critical","TLS private key"),
 ("/wp-config.php.bak","critical","WP config backup"),("/config.php.bak","critical","Config backup"),
 ("/db.sql","critical","SQL dump"),("/dump.sql","critical","SQL dump"),
 ("/actuator/env","critical","Spring actuator env"),("/actuator/heapdump","critical","Spring heapdump"),
 ("/api/v1/namespaces","critical","Kubernetes anonymous API"),("/v2/_catalog","critical","Docker registry catalog"),
 ("/_ignition/health-check","critical","Laravel Ignition RCE"),("/invoker/JMXInvokerServlet","critical","JBoss invoker"),
 ("/swagger.json","high","Swagger spec"),("/openapi.json","high","OpenAPI spec"),
 ("/api/swagger.json","high","Swagger spec (API)"),("/graphql","high","GraphQL endpoint"),
 ("/phpinfo.php","high","phpinfo"),("/info.php","high","phpinfo"),
 ("/server-status","high","Apache status"),("/server-info","high","Apache info"),
 ("/console","high","Werkzeug debug console"),("/debug","high","Debug endpoint"),
 ("/debug/pprof","high","Go pprof"),("/elmah.axd","high","ELMAH errors"),
 ("/trace.axd","high","ASP.NET trace"),("/.svn/entries","high","SVN metadata"),
 ("/.hg/requires","high","Mercurial metadata"),("/.htaccess","high","Apache config"),
 ("/web.config","high","IIS config"),("/backup.zip","high","Backup archive"),
 ("/site.zip","high","Source archive"),("/www.zip","high","Source archive"),
 ("/.npmrc","high","npm token config"),("/jmx-console/","high","JBoss JMX"),
 ("/solr/","high","Solr admin"),("/_cat/indices","high","Elasticsearch indices"),
 ("/metrics","high","Prometheus metrics"),("/telescope/requests","high","Laravel Telescope"),
 ("/adminer.php","high","Adminer DB admin"),("/wp-content/debug.log","high","WP debug log"),
 ("/storage/logs/laravel.log","high","Laravel log"),("/keycloak/","high","Keycloak SSO"),
 ("/n8n","high","n8n automation"),("/consul","high","Consul UI"),
 ("/portainer","high","Portainer"),("/argocd","high","Argo CD"),("/minio","high","MinIO"),
 ("/ray","high","Ray dashboard"),("/.DS_Store","medium","macOS metadata"),
 ("/.well-known/openid-configuration","medium","OIDC config"),("/crossdomain.xml","medium","Flash policy"),
 ("/clientaccesspolicy.xml","medium","Silverlight policy"),("/config.json","medium","Config JSON"),
 ("/package.json","medium","Node manifest"),("/composer.json","medium","PHP manifest"),
 ("/.gitlab-ci.yml","medium","CI config"),("/Dockerfile","medium","Dockerfile"),
 ("/app.log","medium","Application log"),("/error.log","medium","Error log"),
 ("/.vscode/settings.json","medium","IDE settings"),("/.idea/workspace.xml","medium","IDE workspace"),
 ("/gitea","medium","Gitea"),("/backstage","medium","Backstage portal"),
 ("/robots.txt","info","Robots"),("/sitemap.xml","info","Sitemap"),
 ("/.well-known/security.txt","info","Security contact"),("/wp-login.php","info","WordPress login"),
 ("/administrator/","info","Joomla admin"),("/admin/","info","Admin panel"),
 ("/status","info","Status endpoint"),("/health","info","Health endpoint"),
 ("/ui/","info","Generic UI path"),("/version.txt","low","Version disclosure"),
 ("/readme.html","low","CMS readme"),("/CHANGELOG.md","low","Changelog"),
 ("/.dockerenv","low","Docker marker"),
]

WORDLIST = """www mail ftp admin dev api staging test blog shop app portal vpn git jira jenkins wiki docs
status cdn static img media old new beta demo sandbox internal db mysql postgres redis elastic kibana
grafana prometheus vault k8s docker registry s3 backup files cms wp webmail smtp pop imap mx support
help login auth sso id mobile m secure my account billing pay gateway ws api2 v1 v2 qa uat preprod
origin edge cache images video stream download uploads assets store crm erp hr intranet partner chat
meet sip relay proxy fw firewall nas iot monitor monitoring nagios zabbix ops devops ci cd deploy
releases builds artifacts sonar ansible puppet chef terraform consul nomad etcd haproxy nginx tomcat
data bi analytics metrics logs kafka rabbitmq nats zookeeper airflow spark jupyter notebook sentry
loki tempo alertmanager exporter agent collector pipeline ml ai gpu rstudio matomo posthog splunk
logstash graylog jaeger zipkin keycloak gitea gitlab bitbucket nexus harbor argo traefik kong""".split()

INTERESTING_RE = re.compile(
    r'(admin|config|backup|\.env|\.git|\.sql|\.zip|\.bak|\.old|token|secret|password|passwd|upload|'
    r'internal|dev\.|staging|debug|phpinfo|wp-config|\.key|\.pem|id_rsa|actuator|swagger|graphql|'
    r'\.json|\.yaml|\.yml|\.log|\.xml)', re.I)

TECH_SIGS = [
 ('h','server',r'nginx[/ ]?([\d.]+)?','Nginx'),('h','server',r'Apache[/ ]?([\d.]+)?','Apache'),
 ('h','server',r'Microsoft-IIS[/ ]?([\d.]+)?','IIS'),('h','server',r'LiteSpeed','LiteSpeed'),
 ('h','x-powered-by',r'PHP[/ ]?([\d.]+)?','PHP'),('h','x-powered-by',r'ASP\.NET','ASP.NET'),
 ('h','x-powered-by',r'Express','Express'),('h','x-aspnet-version',r'(.+)','ASP.NET'),
 ('h','x-generator',r'(.+)','Generator'),('h','x-drupal-cache',r'.*','Drupal'),
 ('h','x-shopify-stage',r'.*','Shopify'),('h','cf-ray',r'.*','Cloudflare'),
 ('h','x-vercel-id',r'.*','Vercel'),('h','x-amz-cf-id',r'.*','CloudFront'),
 ('h','x-served-by',r'.*','Fastly'),('h','set-cookie',r'JSESSIONID','Java'),
 ('h','set-cookie',r'laravel_session','Laravel'),('h','set-cookie',r'connect\.sid','Node/Express'),
 ('h','set-cookie',r'PHPSESSID','PHP'),('h','set-cookie',r'ASP\.NET_SessionId','ASP.NET'),
 ('b','',r'wp-content/','WordPress'),('b','',r'Powered by Drupal','Drupal'),
 ('b','',r'Joomla!','Joomla'),('b','',r'cdn\.shopify\.com','Shopify'),
 ('b','',r'__NEXT_DATA__','Next.js'),('b','',r'ng-version','Angular'),
 ('b','',r'data-reactroot','React'),('b','',r'__vue__|vue\.js','Vue.js'),
 ('b','',r'jquery[.-]([\d.]+)?','jQuery'),('b','',r'bootstrap[.-]([\d.]+)?','Bootstrap'),
 ('b','',r'cdn-cgi','Cloudflare'),('b','',r'htmx','HTMX'),
]

# ═══════════════════════════ EMITTERS ═══════════════════════════
class QEm:
    """Thread-safe emitter → GUI event queue."""
    def __init__(self, q): self.q = q
    def log(self, msg, level='info'): self.q.put(('log', (level, msg)))
    def finding(self, module, title, severity, detail, evidence=''):
        self.q.put(('finding', (module, title, severity, detail, evidence)))
    def intel(self, section, text): self.q.put(('intel', (section, text)))
    def progress(self, cur, total): self.q.put(('progress', (cur, total)))
    def data(self, key, val): self.q.put(('data', (key, val)))

# ═══════════════════════════ RECON MODULES ═══════════════════════════
def mod_dns(domain, em, cfg):
    em.log('resolving DNS via DoH (3 resolvers · parallel) …', 'sys')
    jobs = [(domain, t) for t in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA')]
    jobs.append(('_dmarc.' + domain, 'TXT'))
    recs = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(doh, n, t, cfg): (n, t) for n, t in jobs}
        for f in as_completed(futs):
            n, t = futs[f]
            key = 'DMARC' if n.startswith('_dmarc.') else t
            try: recs[key] = f.result()
            except Exception: recs[key] = []
    lines = []
    for t, v in recs.items():
        if v: lines.append(f"{t:<7} " + f"\n{'':<7} ".join(str(x)[:90] for x in v[:8]))
    em.intel('DNS RECORDS — ' + domain, '\n'.join(lines) or 'no records returned')
    if not any('v=spf1' in str(x) for x in recs.get('TXT', [])):
        em.finding('dns', 'SPF record missing', 'info', 'No SPF TXT record — spoofing-friendly')
    if not recs.get('DMARC'):
        em.finding('dns', 'DMARC record missing', 'info', 'No _dmarc TXT policy')
    em.log(f"DNS complete — {sum(1 for v in recs.values() if v)} record types", 'ok')
def mod_cert(domain, em, cfg):
    em.log('extracting TLS certificate …', 'sys')
    try:
        with socket.create_connection((domain, 443), timeout=cfg['timeout']) as sock:
            with cfg['ctx'].wrap_socket(sock, server_hostname=domain) as ss:
                cert, proto, cipher = ss.getpeercert(), ss.version(), ss.cipher()[0]
        sans = [v for k, v in cert.get('subjectAltName', ()) if k == 'DNS']
        days = int((ssl.cert_time_to_seconds(cert['notAfter']) - time.time()) / 86400)
        issuer = dict(x[0] for x in cert.get('issuer', ())).get('organizationName', '?')
        txt = (f"issuer    {issuer}\nSANs      {len(sans)} names\n"
               + '\n'.join('          ' + n for n in sans[:25])
               + (f"\n          … +{len(sans)-25} more" if len(sans) > 25 else '')
               + f"\nexpires   {cert['notAfter']} ({days}d)\nproto     {proto} · {cipher}")
        em.intel('TLS CERTIFICATE — ' + domain, txt)
        if days < 14:
            em.finding('cert', 'Certificate expiring soon', 'medium', f'expires in {days} days', cert['notAfter'])
        wild = sum(1 for n in sans if n.startswith('*.'))
        em.finding('cert', f'{len(sans)} SANs discovered', 'info', f'{wild} wildcard names', ', '.join(sans[:8]))
        em.data('cert_sans', sans)
        em.log(f'certificate parsed — {len(sans)} SANs', 'ok')
    except Exception as e:
        em.log(f'certificate check failed → {e}', 'err')

def mod_subs(domain, em, cfg):
    em.log('querying crt.sh certificate transparency …', 'sys')
    subs = {}
    st, _, body, _ = http_request(f'https://crt.sh/?q=%25.{domain}&output=json', cfg, timeout=30)
    if st == 200:
        try:
            for e in json.loads(body):
                for fld in ('name_value', 'common_name'):
                    for n in str(e.get(fld, '')).split('\n'):
                        n = n.strip().lower().lstrip('*.')
                        if n.endswith(domain) and DOMAIN_RE.match(n):
                            subs.setdefault(n, set()).add('CT')
        except Exception: pass
    em.log(f'CT logs → {len(subs)} names', 'ok')
    if not cfg['abort'].is_set():
        em.log(f'DoH brute-force → {len(WORDLIST)} candidates', 'sys')
        total, done, lk = len(WORDLIST), [0], threading.Lock()
        def chk(w):
            if cfg['abort'].is_set(): return (None, None)
            r = doh(f'{w}.{domain}', 'A', cfg)
            with lk: done[0] += 1; em.progress(done[0], total)
            return (f'{w}.{domain}', r)
        with ThreadPoolExecutor(max_workers=25) as ex:
            for name, r in ex.map(chk, WORDLIST):
                if name and r: subs.setdefault(name, set()).add('DNS')
    names = sorted(subs)
    em.intel('SUBDOMAINS — ' + domain,
             '\n'.join(f"{n:<48} [{'+'.join(sorted(subs[n]))}]" for n in names) or 'none found')
    em.finding('subs', f'{len(names)} subdomains discovered', 'info', 'CT logs + DoH brute', ', '.join(names[:10]))
    em.data('subs', names)
    em.log(f'{len(names)} unique subdomains', 'ok')

def mod_wayback(domain, em, cfg, limit=2500):
    em.log('mining Wayback Machine CDX …', 'sys')
    url = (f'https://web.archive.org/cdx/search/cdx?url=*.{domain}*&output=json'
           f'&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit={limit}')
    st, _, body, _ = http_request(url, cfg, timeout=30)
    if st != 200:
        em.log('wayback unavailable', 'err'); return
    try: rows = json.loads(body)[1:]
    except Exception: rows = []
    urls = [r[0] for r in rows]
    hits = [u for u in urls if INTERESTING_RE.search(u)]
    em.intel('WAYBACK — ' + domain,
             f'{len(urls)} archived URLs · {len(hits)} interesting\n\n' + '\n'.join(hits[:150]))
    if hits:
        em.finding('wayback', f'{len(hits)} suspicious historical URLs', 'info',
                   'admin/config/backup/secret patterns', ' ; '.join(hits[:6]))
    em.data('wayback', hits[:500])
    em.log(f'{len(urls)} archived · {len(hits)} interesting', 'ok')

def mod_headers(domain, em, cfg):
    em.log('auditing HTTP security headers …', 'sys')
    st, hdrs, body, final = http_request(f'https://{domain}/', cfg)
    if st is None:
        st, hdrs, body, final = http_request(f'http://{domain}/', cfg)
    if st is None:
        em.log(f'target unreachable → {final}', 'err'); return
    def miss(h, sev, title, detail):
        if h not in hdrs: em.finding('headers', title, sev, detail, f'missing: {h}')
    miss('strict-transport-security', 'medium', 'HSTS missing', 'no HTTPS enforcement')
    miss('content-security-policy', 'low', 'CSP missing', 'no XSS mitigation policy')
    miss('x-content-type-options', 'low', 'X-Content-Type-Options missing', 'MIME sniffing risk')
    miss('x-frame-options', 'low', 'X-Frame-Options missing', 'clickjacking risk')
    miss('referrer-policy', 'info', 'Referrer-Policy missing', 'referrer leakage')
    miss('permissions-policy', 'info', 'Permissions-Policy missing', 'feature policy absent')
    if hdrs.get('access-control-allow-origin') == '*':
        em.finding('headers', 'Wildcard CORS', 'medium', 'Access-Control-Allow-Origin: *', '*')
    for ck in hdrs.get('set-cookie', '').split(','):
        nm = ck.split('=')[0].strip()
        if not nm: continue
        if 'secure' not in ck.lower():
            em.finding('headers', f'Cookie "{nm}" w/o Secure', 'medium', 'cookie sent over HTTP', nm)
        if 'httponly' not in ck.lower():
            em.finding('headers', f'Cookie "{nm}" w/o HttpOnly', 'low', 'JS-accessible cookie', nm)
    for lk in ('server', 'x-powered-by', 'x-aspnet-version'):
        if hdrs.get(lk):
            em.finding('headers', f'Version disclosure ({lk})', 'low', 'banner grabbing enabled', hdrs[lk])
    text = body.decode('utf-8', 'ignore'); tech = []
    for kind, key, rx, name in TECH_SIGS:
        hay = hdrs.get(key, '') if kind == 'h' else text
        m = re.search(rx, hay, re.I)
        if m: tech.append(name + (f' {m.group(1)}' if m.lastindex else ''))
    tech = list(dict.fromkeys(tech))
    lines = [f'response    {st} → {final[:90]}', f'server      {hdrs.get("server", "—")}', '', 'TECH STACK']
    lines += [f'  ▸ {t}' for t in tech] or ['  ▸ (none fingerprinted)']
    lines += ['', 'HEADER MATRIX']
    for h in ('strict-transport-security', 'content-security-policy', 'x-content-type-options',
              'x-frame-options', 'referrer-policy', 'permissions-policy'):
        lines.append(f'  {"✓" if h in hdrs else "✗"} {h}')
    em.intel('HEADERS & TECH — ' + domain, '\n'.join(lines))
    em.data('tech', tech)
    em.log(f'headers audited — {len(tech)} technologies fingerprinted', 'ok')

def mod_probe(domain, em, cfg, threads=25):
    em.log(f'probing {len(PROBES)} paths · {threads} threads …', 'sys')
    base = f'https://{domain}'
    st0, _, _, _ = http_request(base + '/', cfg, max_read=1024)
    if st0 is None:
        base = f'http://{domain}'
        st0, _, _, _ = http_request(base + '/', cfg, max_read=1024)
    if st0 is None:
        em.log('target unreachable — probe aborted', 'err'); return
    rnd = ''.join(random.choices('abcdef0123456789', k=14))
    bst, _, bb, _ = http_request(f'{base}/nx-{rnd}', cfg, max_read=65536)
    bl = len(bb) if bst is not None else None
    em.log(f'base {base} · soft-404 baseline {"ON" if bl is not None else "OFF"}', 'sys')
    total, done, lk, hits = len(PROBES), [0], threading.Lock(), []
    def one(item):
        if cfg['abort'].is_set(): return None
        path, sev, label = item
        st, hh, body, final = http_request(base + path, cfg, max_read=65536)
        with lk: done[0] += 1; em.progress(done[0], total)
        if st is None or st == 404: return None
        if bl is not None and st in (200, 403) and abs(len(body) - bl) <= 32: return None
        if st in (200, 206) and len(body) == 0: return None
        return (path, sev, label, st, len(body), hh.get('content-type', ''), hh.get('location', ''))
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(one, PROBES):
            if r: hits.append(r)
    hits.sort(key=lambda x: (SEV_ORDER.index(x[1]), -x[4]))
    lines = []
    for path, sev, label, st, size, ct, loc in hits:
        lines.append(f'[{sev.upper():^8}] {st} {path:<38} {hb(size):>7} · {ct[:26]}'
                     + (f' → {loc[:40]}' if loc else ''))
        if st == 403:
            em.finding('probe', f'Protected path: {path}', 'info', label, f'403 · {hb(size)}')
        else:
            em.finding('probe', f'{label} → {path}', sev if st in (200, 206, 401) else 'info',
                       f'HTTP {st} on {base}{path}', f'{st} · {hb(size)} · {ct[:40]}')
    em.intel('PATH PROBING — ' + domain,
             f'{len(hits)} live vectors on {base}\n\n' + ('\n'.join(lines) or 'nothing exposed'))
    em.log(f'{len(hits)} live vectors found', 'ok' if hits else 'info')

def mod_passive(domain, em, cfg):
    phases = (('dns', mod_dns), ('cert', mod_cert), ('subs', mod_subs), ('wayback', mod_wayback))
    for i, (name, fn) in enumerate(phases, 1):
        if cfg['abort'].is_set(): em.log('aborted by operator', 'warn'); return
        em.log(f'phase {i}/4 → {name.upper()}', 'sys')
        try:
            fn(domain, em, cfg)
        except Exception as e:
            em.log(f'{name} phase failed → {e} — continuing', 'err')

def mod_full(domain, em, cfg):
    mod_passive(domain, em, cfg)
    for i, (name, fn) in enumerate((('headers', mod_headers), ('probe', mod_probe)), 5):
        if cfg['abort'].is_set(): return
        em.log(f'phase {i}/6 → {name.upper()}', 'sys')
        try:
            fn(domain, em, cfg)
        except Exception as e:
            em.log(f'{name} phase failed → {e} — continuing', 'err')
MODULES = [
    ('full',    '▮ FULL RECON',   True,  mod_full,    COL['grn']),
    ('passive', '▮ PASSIVE ONLY', False, mod_passive, COL['cyn']),
    ('dns',     '  DNS RECORDS',  False, mod_dns,     COL['blu']),
    ('cert',    '  TLS CERT',     False, mod_cert,    COL['mag']),
    ('subs',    '  SUBDOMAINS',   False, mod_subs,    COL['cyn']),
    ('wayback', '  WAYBACK',      False, mod_wayback, COL['amb']),
    ('headers', '  HEADER AUDIT', True,  mod_headers, COL['amb']),
    ('probe',   '  PATH PROBE',   True,  mod_probe,   COL['red']),
]

# ═══════════════════════════ GUI ═══════════════════════════
class Nexus(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f'RECON//NEXUS v{VERSION} — Smart Pentest Recon Engine')
        self.configure(bg=COL['bg0'])
        w, h = 1380, 840
        x = max(0, (self.winfo_screenwidth() - w) // 2)
        y = max(0, (self.winfo_screenheight() - h) // 2)
        self.geometry(f'{w}x{h}+{x}+{y}'); self.minsize(1120, 700)

        # fonts
        fams = set(tkfont.families())
        def F(cands, size, weight='normal'):
            for c in cands:
                if c in fams: return (c, size, weight)
            return ('TkFixedFont', size, weight)
        mono_c = ['Cascadia Code', 'JetBrains Mono', 'Consolas', 'Menlo', 'DejaVu Sans Mono']
        ui_c = ['Segoe UI', 'Helvetica', 'Noto Sans']
        self.F_D = F(mono_c, 17, 'bold');  self.F_DS = F(mono_c, 8)
        self.F_M = F(mono_c, 10);          self.F_MB = F(mono_c, 10, 'bold')
        self.F_MS = F(mono_c, 9);          self.F_MT = F(mono_c, 8)
        self.F_U = F(ui_c, 9);             self.F_UB = F(ui_c, 9, 'bold')
        self.F_BIG = F(mono_c, 19, 'bold'); self.F_TINY = F(mono_c, 7)

        # state
        self.q = queue.Queue()
        self.target = None
        self.authorized = False
        self.busy = False
        self.abort = threading.Event()
        self.findings = []; self.fmap = {}; self.fcount = 0
        self.info = {}
        self.rang = 0; self.led_on = True
        self.cfg = {'timeout': 10, 'proxy': None, 'ctx': ssl.create_default_context(),
                    'ua': DEFAULT_UA, 'abort': self.abort}

        self.build_styles()
        self.build_header()
        self.build_targetbar()
        self.build_main()
        self.build_statusbar()

        self.after(80, self.pump)
        self.after(45, self.radar_tick)
        self.after(1000, self.clock_tick)
        self.after(900, self.led_tick)
        boot = [
            ('sys', f'RECON//NEXUS v{VERSION} GUI — kernel online'),
            ('sys', f'{N_DORKS} dork payloads armed across {len(DORKS)} attack vectors'),
            ('sys', 'severity matrix calibrated — CRITICAL / HIGH / MEDIUM / LOW / INFO'),
            ('info', 'keyless intel linked — crt.sh · Cloudflare DoH · Wayback CDX'),
            ('ok', 'zero dependencies · zero API keys · engine ready'),
            ('sys', 'awaiting target acquisition — lock a domain to begin'),
        ]
        for i, (lv, m) in enumerate(boot):
            self.after(300 + i * 320, lambda lv=lv, m=m: self.ops_log(lv, m))

    # ── styles ──
    def build_styles(self):
        st = ttk.Style(self); st.theme_use('clam')
        st.configure('Treeview', background=COL['panel'], fieldbackground=COL['panel'],
                     foreground=COL['txt'], rowheight=25, borderwidth=0, font=self.F_MS)
        st.configure('Treeview.Heading', background=COL['panel2'], foreground=COL['grn'],
                     font=self.F_UB, relief='flat', padding=6)
        st.map('Treeview', background=[('selected', COL['sel'])],
               foreground=[('selected', COL['bright'])])
        st.map('Treeview.Heading', background=[('active', COL['line2'])])
        st.configure('nex.TNotebook', background=COL['bg0'], borderwidth=0, tabmargins=0)
        st.configure('nex.TNotebook.Tab', background=COL['panel'], foreground=COL['dim'],
                     padding=[16, 8], font=self.F_UB)
        st.map('nex.TNotebook.Tab', background=[('selected', COL['grn'])],
               foreground=[('selected', '#04120c')], expand=[('selected', [0, 0, 0, 0])])
        st.configure('nex.Horizontal.TProgressbar', troughcolor=COL['line'],
                     background=COL['grn'], borderwidth=0, thickness=7)
        st.configure('TCombobox', fieldbackground=COL['panel'], background=COL['panel2'],
                     foreground=COL['txt'], arrowcolor=COL['grn'], borderwidth=0)
        st.configure('Vertical.TScrollbar', background=COL['line2'], troughcolor=COL['bg0'],
                     borderwidth=0, arrowsize=0)
        self.option_add('*TCombobox*Listbox.background', COL['panel2'])
        self.option_add('*TCombobox*Listbox.foreground', COL['txt'])
        self.option_add('*TCombobox*Listbox.selectBackground', COL['sel'])
        self.option_add('*TCombobox*Listbox.font', self.F_MS)

    # ── header ──
    def build_header(self):
        hd = tk.Frame(self, bg=COL['bg0']); hd.pack(fill='x', padx=16, pady=(12, 6))
        self.radar = tk.Canvas(hd, width=38, height=38, bg=COL['bg0'], highlightthickness=0)
        self.radar.pack(side='left')
        for r in (16, 11, 6):
            self.radar.create_oval(19-r, 19-r, 19+r, 19+r, outline='#1d4a38')
        self.radar.create_line(3, 19, 35, 19, fill='#12352a'); self.radar.create_line(19, 3, 19, 35, fill='#12352a')
        tk.Label(hd, text='RECON', bg=COL['bg0'], fg=COL['bright'], font=self.F_D).pack(side='left', padx=(10, 0))
        tk.Label(hd, text='//', bg=COL['bg0'], fg=COL['grn'], font=self.F_D).pack(side='left')
        tk.Label(hd, text='NEXUS', bg=COL['bg0'], fg=COL['bright'], font=self.F_D).pack(side='left')
        sub = tk.Frame(hd, bg=COL['bg0']); sub.pack(side='left', padx=(14, 0), fill='y')
        tk.Label(sub, text=f'SMART PENTEST RECON ENGINE · v{VERSION}', bg=COL['bg0'],
                 fg=COL['dim'], font=self.F_MT).pack(anchor='w', pady=(4, 0))
        tk.Label(sub, text='ZERO-DEPS · NO API KEYS · by empsolohk', bg=COL['bg0'],
                 fg=COL['mag'], font=self.F_MT).pack(anchor='w')
        self.clock_lbl = tk.Label(hd, text='--:--:-- UTC', bg=COL['bg0'], fg=COL['cyn'], font=self.F_MB)
        self.clock_lbl.pack(side='right', padx=(12, 0))
        self.led_lbl = tk.Label(hd, text='●', bg=COL['bg0'], fg=COL['grn'], font=self.F_M)
        self.led_lbl.pack(side='right')
        tk.Label(hd, text='ENGINE', bg=COL['bg0'], fg=COL['dim'], font=self.F_MT).pack(side='right', padx=(0, 4))
        self.scope_lbl = tk.Label(hd, text='SCOPE: —', bg=COL['bg0'], fg=COL['amb'], font=self.F_MS)
        self.scope_lbl.pack(side='right', padx=(0, 16))

    # ── target bar ──
    def build_targetbar(self):
        bar = tk.Frame(self, bg=COL['panel'], highlightbackground=COL['line'], highlightthickness=1)
        bar.pack(fill='x', padx=16, pady=6)
        tk.Label(bar, text='▍TARGET ACQUISITION', bg=COL['panel'], fg=COL['grn'],
                 font=self.F_UB).pack(side='left', padx=(12, 0), pady=(4, 0))
        tk.Label(bar, text='⚠ AUTHORIZED SCOPE ONLY', bg=COL['panel'], fg=COL['amb'],
                 font=self.F_MT).pack(side='right', padx=(0, 12), pady=(4, 0))
        row = tk.Frame(bar, bg=COL['panel']); row.pack(fill='x', padx=12, pady=(2, 12))
        tk.Label(row, text='root@nexus:~$', bg=COL['panel'], fg=COL['grn'], font=self.F_MB).pack(side='left')
        tk.Label(row, text='./acquire --domain', bg=COL['panel'], fg=COL['dim'], font=self.F_M).pack(side='left', padx=(6, 10))
        self.target_var = tk.StringVar()
        ent = tk.Entry(row, textvariable=self.target_var, bg='#060b15', fg=COL['bright'],
                       insertbackground=COL['grn'], font=self.F_MB, bd=0,
                       highlightthickness=1, highlightcolor=COL['grn'], highlightbackground=COL['line2'])
        ent.pack(side='left', fill='x', expand=True, ipady=7, padx=(0, 10))
        ent.bind('<Return>', lambda e: self.lock_target())
        tk.Button(row, text='CLEAR', command=self.clear_target, relief='flat', cursor='hand2',
                  bg=COL['panel2'], fg=COL['dim'], activeforeground=COL['red'],
                  activebackground=COL['line2'], font=self.F_MS, padx=14, pady=6).pack(side='right')
        tk.Button(row, text='LOCK TARGET', command=self.lock_target, relief='flat', cursor='hand2',
                  bg=COL['grn'], fg='#04120c', activebackground='#5cf0c0',
                  font=self.F_MB, padx=18, pady=6).pack(side='right', padx=(0, 8))

    # ── main 3-column ──
    def build_main(self):
        main = tk.Frame(self, bg=COL['bg0']); main.pack(fill='both', expand=True, padx=16, pady=4)
        main.columnconfigure(1, weight=1); main.rowconfigure(0, weight=1)
        self.build_rail(main)
        self.build_results(main)
        self.build_side(main)

    def rail_btn(self, parent, text, color, cmd):
        b = tk.Button(parent, text=text, command=cmd, anchor='w', relief='flat', cursor='hand2',
                      bg=COL['panel'], fg=COL['txt'], activebackground=COL['panel2'],
                      activeforeground=color, font=self.F_M, padx=12, pady=7, bd=0)
        b.pack(fill='x', padx=10, pady=2); b._acc = color
        b.bind('<Enter>', lambda e, b=b: b.config(fg=b._acc, bg=COL['panel2']))
        b.bind('<Leave>', lambda e, b=b: b.config(fg=COL['txt'], bg=COL['panel']))
        self.mod_buttons.append(b)

    def build_rail(self, parent):
        rail = tk.Frame(parent, bg=COL['bg0'], width=172)
        rail.grid(row=0, column=0, sticky='ns', padx=(0, 10)); rail.grid_propagate(False)
        self.mod_buttons = []
        tk.Label(rail, text='PIPELINE', bg=COL['bg0'], fg=COL['dim'], font=self.F_MT).pack(anchor='w', padx=12, pady=(2, 4))
        for key, label, active, fn, color in MODULES[:2]:
            self.rail_btn(rail, label, color, lambda k=key: self.run_module(k))
        tk.Frame(rail, bg=COL['line'], height=1).pack(fill='x', padx=12, pady=8)
        tk.Label(rail, text='SINGLE MODULES', bg=COL['bg0'], fg=COL['dim'], font=self.F_MT).pack(anchor='w', padx=12, pady=(0, 4))
        for key, label, active, fn, color in MODULES[2:]:
            self.rail_btn(rail, label, color, lambda k=key: self.run_module(k))
        tk.Frame(rail, bg=COL['line'], height=1).pack(fill='x', padx=12, pady=8)
        self.abort_btn = tk.Button(rail, text='■ ABORT SCAN', relief='flat', cursor='hand2', anchor='w',
                                   bg=COL['panel'], fg=COL['red'], activebackground=COL['panel2'],
                                   font=self.F_M, padx=12, pady=7, state='disabled',
                                   disabledforeground=COL['dim'], command=self.do_abort)
        self.abort_btn.pack(fill='x', padx=10, pady=2)
        tk.Label(rail, text='active modules require\nauthorization confirmation', bg=COL['bg0'],
                 fg=COL['dim'], font=self.F_TINY, justify='left').pack(anchor='w', padx=12, pady=(14, 0))

    def tbtn(self, parent, text, color, cmd):
        b = tk.Button(parent, text=text, command=cmd, relief='flat', cursor='hand2',
                      bg=COL['panel2'], fg=color, activebackground=COL['line2'],
                      activeforeground=color, font=self.F_MS, padx=10, pady=4, bd=0)
        b.pack(side='left', padx=2); return b

    def build_results(self, parent):
        wrap = tk.Frame(parent, bg=COL['bg0']); wrap.grid(row=0, column=1, sticky='nsew')
        wrap.rowconfigure(0, weight=1); wrap.columnconfigure(0, weight=1)
        self.nb = ttk.Notebook(wrap, style='nex.TNotebook')
        self.nb.grid(row=0, column=0, sticky='nsew')

        # FINDINGS tab
        f1 = tk.Frame(self.nb, bg=COL['panel']); self.nb.add(f1, text='  FINDINGS  ')
        tb1 = tk.Frame(f1, bg=COL['panel']); tb1.pack(fill='x', padx=8, pady=8)
        self.tbtn(tb1, 'EXPORT JSON', COL['grn'], self.export_json)
        self.tbtn(tb1, 'EXPORT MD', COL['cyn'], self.export_md)
        self.tbtn(tb1, 'CLEAR', COL['amb'], self.clear_findings)
        self.find_count_lbl = tk.Label(tb1, text='0 findings', bg=COL['panel'], fg=COL['dim'], font=self.F_MS)
        self.find_count_lbl.pack(side='right', padx=8)
        tvw = tk.Frame(f1, bg=COL['panel']); tvw.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        cols = ('sev', 'module', 'title', 'evidence')
        self.ftree = ttk.Treeview(tvw, columns=cols, show='headings', selectmode='browse')
        for c, w, a in (('sev', 82, 'center'), ('module', 86, 'center'), ('title', 360, 'w'), ('evidence', 560, 'w')):
            self.ftree.heading(c, text=c.upper())
            self.ftree.column(c, width=w, anchor=a, stretch=c == 'evidence')
        for sev, colr in SEVC.items(): self.ftree.tag_configure(sev, foreground=colr)
        fsb = ttk.Scrollbar(tvw, orient='vertical', command=self.ftree.yview)
        self.ftree.configure(yscrollcommand=fsb.set)
        self.ftree.pack(side='left', fill='both', expand=True); fsb.pack(side='right', fill='y')
        self.ftree.bind('<Double-1>', self.show_finding)

        # DORK ARSENAL tab
        f2 = tk.Frame(self.nb, bg=COL['panel']); self.nb.add(f2, text='  DORK ARSENAL  ')
        tb2 = tk.Frame(f2, bg=COL['panel']); tb2.pack(fill='x', padx=8, pady=8)
        self.dcat_var = tk.StringVar(value='ALL')
        self.dsev_var = tk.StringVar(value='ALL')
        self.eng_var = tk.StringVar(value='GOOGLE')
        tk.Label(tb2, text='VECTOR', bg=COL['panel'], fg=COL['dim'], font=self.F_MT).pack(side='left', padx=(4, 4))
        ttk.Combobox(tb2, textvariable=self.dcat_var, width=22, state='readonly',
                     values=['ALL'] + [c[0] for c in DORKS]).pack(side='left', padx=(0, 10))
        tk.Label(tb2, text='SEV', bg=COL['panel'], fg=COL['dim'], font=self.F_MT).pack(side='left', padx=(0, 4))
        ttk.Combobox(tb2, textvariable=self.dsev_var, width=9, state='readonly',
                     values=['ALL'] + SEV_ORDER).pack(side='left', padx=(0, 10))
        tk.Label(tb2, text='ENGINE', bg=COL['panel'], fg=COL['dim'], font=self.F_MT).pack(side='left', padx=(0, 4))
        ttk.Combobox(tb2, textvariable=self.eng_var, width=11, state='readonly',
                     values=list(ENGINES)).pack(side='left', padx=(0, 12))
        self.tbtn(tb2, 'COPY', COL['grn'], self.copy_dork)
        self.tbtn(tb2, 'OPEN ↗', COL['cyn'], self.open_dork)
        self.tbtn(tb2, 'COPY ALL', COL['grn'], self.copy_all_dorks)
        self.tbtn(tb2, 'OPEN ALL ⚠', COL['amb'], self.open_all_dorks)
        self.dcount_lbl = tk.Label(tb2, text=f'{N_DORKS} payloads', bg=COL['panel'], fg=COL['dim'], font=self.F_MS)
        self.dcount_lbl.pack(side='right', padx=8)
        self.dcat_var.trace_add('write', lambda *a: self.render_dorks())
        self.dsev_var.trace_add('write', lambda *a: self.render_dorks())
        dvw = tk.Frame(f2, bg=COL['panel']); dvw.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        dcols = ('sev', 'category', 'label', 'query')
        self.dtree = ttk.Treeview(dvw, columns=dcols, show='headings', selectmode='browse')
        for c, w, a in (('sev', 82, 'center'), ('category', 170, 'w'), ('label', 210, 'w'), ('query', 620, 'w')):
            self.dtree.heading(c, text=c.upper())
            self.dtree.column(c, width=w, anchor=a, stretch=c == 'query')
        for sev, colr in SEVC.items(): self.dtree.tag_configure(sev, foreground=colr)
        dsb = ttk.Scrollbar(dvw, orient='vertical', command=self.dtree.yview)
        self.dtree.configure(yscrollcommand=dsb.set)
        self.dtree.pack(side='left', fill='both', expand=True); dsb.pack(side='right', fill='y')

        # INTEL tab
        f3 = tk.Frame(self.nb, bg=COL['panel']); self.nb.add(f3, text='  INTEL DATA  ')
        tb3 = tk.Frame(f3, bg=COL['panel']); tb3.pack(fill='x', padx=8, pady=8)
        self.tbtn(tb3, 'COPY', COL['grn'], lambda: self.copy_text(self.intel_t.get('1.0', 'end')))
        self.tbtn(tb3, 'CLEAR', COL['amb'], lambda: (self.intel_t.config(state='normal'),
                                                     self.intel_t.delete('1.0', 'end'),
                                                     self.intel_t.config(state='disabled')))
        self.intel_t = tk.Text(f3, bg='#060b15', fg=COL['txt'], font=self.F_MS, bd=0,
                               highlightthickness=0, wrap='none', state='disabled', padx=10, pady=8)
        self.intel_t.tag_configure('sec', foreground=COL['grn'], font=self.F_MB)
        self.intel_t.tag_configure('dim', foreground=COL['dim'])
        isb = ttk.Scrollbar(f3, orient='vertical', command=self.intel_t.yview)
        self.intel_t.configure(yscrollcommand=isb.set)
        self.intel_t.pack(side='left', fill='both', expand=True, padx=8, pady=(0, 8)); isb.pack(side='right', fill='y', pady=(0, 8))

    def panel(self, parent, title):
        f = tk.Frame(parent, bg=COL['panel'], highlightbackground=COL['line'], highlightthickness=1)
        h = tk.Frame(f, bg=COL['panel']); h.pack(fill='x', padx=12, pady=(10, 0))
        tk.Label(h, text='▍' + title, bg=COL['panel'], fg=COL['grn'], font=self.F_UB).pack(side='left')
        tk.Frame(h, bg=COL['line'], height=1).pack(side='left', fill='x', expand=True, padx=(8, 0))
        body = tk.Frame(f, bg=COL['panel']); body.pack(fill='both', expand=True, padx=12, pady=10)
        return f, body

    def build_side(self, parent):
        side = tk.Frame(parent, bg=COL['bg0'], width=330)
        side.grid(row=0, column=2, sticky='ns', padx=(10, 0)); side.grid_propagate(False)
        side.rowconfigure(1, weight=1); side.columnconfigure(0, weight=1)

        tp, tb = self.panel(side, 'MISSION TELEMETRY')
        tp.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        box = tk.Frame(tb, bg=COL['bg1'], highlightbackground=COL['line'], highlightthickness=1)
        box.pack(fill='x')
        tk.Label(box, text='LOCKED TARGET', bg=COL['bg1'], fg=COL['dim'], font=self.F_TINY).pack(anchor='w', padx=10, pady=(7, 0))
        self.tel_target = tk.Label(box, text='—', bg=COL['bg1'], fg=COL['grn'], font=self.F_MB, anchor='w')
        self.tel_target.pack(anchor='w', padx=10, pady=(0, 7))
        g = tk.Frame(tb, bg=COL['panel']); g.pack(fill='x', pady=(8, 0))
        for i in range(3): g.columnconfigure(i, weight=1)
        self.sev_lbls = {}
        for i, sev in enumerate(SEV_ORDER):
            cell = tk.Frame(g, bg=COL['bg1'], highlightbackground=COL['line'], highlightthickness=1)
            cell.grid(row=0 if i < 3 else 1, column=i % 3, sticky='nsew', padx=2, pady=2)
            n = tk.Label(cell, text='0', bg=COL['bg1'], fg=SEVC[sev], font=self.F_BIG)
            n.pack(pady=(6, 0))
            tk.Label(cell, text=sev.upper(), bg=COL['bg1'], fg=COL['dim'], font=self.F_TINY).pack(pady=(0, 5))
            self.sev_lbls[sev] = n
        self.sev_counts = {s: 0 for s in SEV_ORDER}
        pf = tk.Frame(tb, bg=COL['panel']); pf.pack(fill='x', pady=(10, 0))
        tk.Label(pf, text='SCAN PROGRESS', bg=COL['panel'], fg=COL['dim'], font=self.F_TINY).pack(anchor='w')
        self.prog = ttk.Progressbar(pf, style='nex.Horizontal.TProgressbar', mode='determinate', maximum=100)
        self.prog.pack(fill='x', pady=(5, 3))
        self.prog_lbl = tk.Label(pf, text='idle', bg=COL['panel'], fg=COL['dim'], font=self.F_MT, anchor='w')
        self.prog_lbl.pack(fill='x')

        lp, lb = self.panel(side, 'OPS LOG — LIVE FEED')
        lp.grid(row=1, column=0, sticky='nsew'); lb.rowconfigure(0, weight=1); lb.columnconfigure(0, weight=1)
        self.log_t = tk.Text(lb, bg='#060b15', fg=COL['txt'], font=self.F_MT, bd=0, wrap='word',
                             highlightthickness=0, state='disabled', padx=8, pady=6)
        for lv, colr in LOGC.items(): self.log_t.tag_configure(lv, foreground=colr)
        lsb = ttk.Scrollbar(lb, orient='vertical', command=self.log_t.yview)
        self.log_t.configure(yscrollcommand=lsb.set)
        self.log_t.grid(row=0, column=0, sticky='nsew'); lsb.grid(row=0, column=1, sticky='ns')

    def build_statusbar(self):
        sb = tk.Frame(self, bg=COL['panel'], highlightbackground=COL['line'], highlightthickness=1)
        sb.pack(fill='x', side='bottom', padx=16, pady=(4, 12))
        self.state_lbl = tk.Label(sb, text='● IDLE', bg=COL['panel'], fg=COL['grn'], font=self.F_MS)
        self.state_lbl.pack(side='left', padx=12, pady=6)
        tk.Label(sb, text='threads: 25 · engine: keyless · tls: verified', bg=COL['panel'],
                 fg=COL['dim'], font=self.F_MT).pack(side='left', padx=4)
        tk.Label(sb, text=f'RECON//NEXUS v{VERSION} · by empsolohk · authorized use only',
                 bg=COL['panel'], fg=COL['mag'], font=self.F_MT).pack(side='right', padx=12)

    # ── ambient motion ──
    def radar_tick(self):
        c = self.radar; c.delete('sw')
        self.rang = (self.rang + 5) % 360
        for k, shade in enumerate((COL['grn'], '#1d9a70', '#12604a', '#0b3a2e')):
            a = math.radians(self.rang - k * 15)
            c.create_line(19, 19, 19 + 15 * math.cos(a), 19 - 15 * math.sin(a),
                          fill=shade, width=2 if k == 0 else 1, tags='sw')
        self.after(45, self.radar_tick)

    def led_tick(self):
        self.led_on = not self.led_on
        col = COL['amb'] if self.busy else COL['grn']
        self.led_lbl.config(fg=col if self.led_on else COL['dim'])
        self.after(650 if self.busy else 1100, self.led_tick)

    def clock_tick(self):
        self.clock_lbl.config(text=datetime.now(timezone.utc).strftime('%H:%M:%S') + ' UTC')
        self.after(1000, self.clock_tick)

    # ── event pump (thread → UI) ──
    def pump(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == 'log': self.ops_log(*payload)
                elif kind == 'finding': self.add_finding(*payload)
                elif kind == 'intel': self.add_intel(*payload)
                elif kind == 'progress': self.set_progress(*payload)
                elif kind == 'data': self.info[payload[0]] = payload[1]
                elif kind == 'done': self.scan_done()
        except queue.Empty:
            pass
        self.after(80, self.pump)

    def ops_log(self, level, msg):
        t = self.log_t; t.config(state='normal')
        ts = datetime.now().strftime('%H:%M:%S')
        t.insert('end', f'[{ts}] ', 'ts')
        t.insert('end', f'▸ {msg}\n', level)
        t.see('end'); t.config(state='disabled')

    def add_intel(self, section, text):
        t = self.intel_t; t.config(state='normal')
        t.insert('end', f'\n┌─ {section} ', 'sec')
        t.insert('end', '─' * max(2, 52 - len(section)) + '\n', 'dim')
        t.insert('end', text + '\n')
        t.see('end'); t.config(state='disabled')
        self.nb.select(2)

    def add_finding(self, module, title, severity, detail, evidence):
        rec = {'module': module, 'title': title, 'severity': severity,
               'detail': detail, 'evidence': evidence, 'time': datetime.now().isoformat()}
        self.findings.append(rec)
        iid = str(self.fcount); self.fcount += 1
        self.fmap[iid] = rec
        self.ftree.insert('', 0, iid=iid, tags=(severity,),
                          values=(severity.upper(), module, title, evidence[:140]))
        self.sev_counts[severity] += 1
        self.sev_lbls[severity].config(text=str(self.sev_counts[severity]))
        self.find_count_lbl.config(text=f'{len(self.findings)} findings')
        self.nb.select(0)

    def set_progress(self, cur, total):
        self.prog['value'] = cur / total * 100 if total else 0
        self.prog_lbl.config(text=f'{cur}/{total} · {cur/total*100:.0f}%' if total else 'idle')

    # ── actions ──
    def lock_target(self):
        v = normalize_domain(self.target_var.get())
        if not DOMAIN_RE.match(v):
            messagebox.showwarning('INVALID TARGET', f'"{v or "∅"}" is not a valid domain.\nExample: example.com')
            return
        self.target = v
        self.tel_target.config(text=v)
        self.scope_lbl.config(text='SCOPE: ' + v)
        self.render_dorks()
        self.ops_log('sys', f'TARGET LOCKED → {v} · {N_DORKS} payloads re-armed')
        self.ops_log('info', 'recon scope active — authorized targets only')

    def clear_target(self):
        self.target = None
        self.target_var.set('')
        self.tel_target.config(text='—')
        self.scope_lbl.config(text='SCOPE: —')
        self.render_dorks()
        self.ops_log('warn', 'target released — payloads disarmed')

    def render_dorks(self):
        for i in self.dtree.get_children(): self.dtree.delete(i)
        cat, sev, n = self.dcat_var.get(), self.dsev_var.get(), 0
        tgt = self.target or '{TARGET}'
        for cname, dorks in DORKS:
            if cat != 'ALL' and cname != cat: continue
            for label, q, s, direct in dorks:
                if sev != 'ALL' and s != sev: continue
                self.dtree.insert('', 'end', tags=(s,),
                                  values=(s.upper(), cname, label, q.replace('{t}', tgt)))
                n += 1
        self.dcount_lbl.config(text=f'{n}/{N_DORKS} payloads')

    def selected_dork(self):
        sel = self.dtree.selection()
        if not sel:
            messagebox.showinfo('NO SELECTION', 'Select a payload row first.')
            return None
        return self.dtree.item(sel[0])['values']

    def copy_text(self, s):
        self.clipboard_clear(); self.clipboard_append(s); self.update()
        self.ops_log('info', f'copied {len(s)} chars to clipboard')

    def copy_dork(self):
        v = self.selected_dork()
        if v: self.copy_text(str(v[3]))

    def open_dork(self):
        v = self.selected_dork()
        if not v: return
        if not self.target:
            messagebox.showwarning('NO TARGET', 'Lock a target domain first.')
            return
        q = str(v[3])
        url = q if q.startswith('http') else ENGINES[self.eng_var.get()].format(urllib.parse.quote(q))
        webbrowser.open(url, new=2)
        self.ops_log('ok', f'opened → {v[2]}')

    def copy_all_dorks(self):
        rows = [str(self.dtree.item(i)['values'][3]) for i in self.dtree.get_children()]
        if rows: self.copy_text('\n'.join(rows))

    def open_all_dorks(self):
        if not self.target:
            messagebox.showwarning('NO TARGET', 'Lock a target domain first.')
            return
        items = list(self.dtree.get_children())[:8]
        if not items: return
        self.ops_log('warn', f'burst open {len(items)} tabs — allow popups')
        def burst():
            for i in items:
                q = str(self.dtree.item(i)['values'][3])
                url = q if q.startswith('http') else ENGINES[self.eng_var.get()].format(urllib.parse.quote(q))
                webbrowser.open(url, new=2); time.sleep(1.3)
            self.q.put(('log', ('ok', 'browser burst complete')))
        threading.Thread(target=burst, daemon=True).start()

    def ensure_auth(self):
        if self.authorized: return True
        ok = messagebox.askyesno('⚠ AUTHORIZATION REQUIRED',
            'This module performs ACTIVE scanning of the target.\n\n'
            'Scanning systems without explicit written authorization is illegal '
            'in most jurisdictions.\n\nDo you have explicit permission to test this target?')
        self.authorized = ok
        if not ok: self.ops_log('warn', 'authorization declined — module blocked')
        return ok

    def run_module(self, key):
        if self.busy:
            self.ops_log('warn', 'scan already in progress — abort first')
            return
        if not self.target:
            messagebox.showwarning('NO TARGET', 'Lock a target domain first.')
            return
        mod = next(m for m in MODULES if m[0] == key)
        if mod[2] and not self.ensure_auth(): return
        self.busy = True; self.abort.clear()
        self.prog['value'] = 0; self.prog_lbl.config(text='starting …')
        self.state_lbl.config(text='● SCANNING', fg=COL['amb'])
        for b in self.mod_buttons: b.config(state='disabled', disabledforeground=COL['dim'])
        self.abort_btn.config(state='normal', fg=COL['red'])
        self.ops_log('sys', f'module launched → {key.upper()} · target {self.target}')
        threading.Thread(target=self._worker, args=(key, mod[3]), daemon=True).start()

    def _worker(self, key, fn):
        em = QEm(self.q); t0 = time.time()
        try:
            fn(self.target, em, self.cfg)
            em.log(f'{key.upper()} complete in {time.time()-t0:.1f}s', 'ok')
        except Exception as e:
            em.log(f'{key} error → {e}', 'err')
        self.q.put(('done', key))

    def do_abort(self):
        self.abort.set()
        self.ops_log('warn', 'abort signal sent — finishing in-flight requests …')

    def scan_done(self):
        self.busy = False
        self.state_lbl.config(text='● IDLE', fg=COL['grn'])
        for b in self.mod_buttons: b.config(state='normal', fg=COL['txt'])
        self.abort_btn.config(state='disabled', disabledforeground=COL['dim'])
        self.prog_lbl.config(text='idle')

    def show_finding(self, ev):
        sel = self.ftree.selection()
        if not sel: return
        rec = self.fmap[sel[0]]
        d = tk.Toplevel(self)
        d.title('FINDING DETAIL'); d.configure(bg=COL['panel'])
        d.geometry('640x380'); d.transient(self)
        tk.Label(d, text=rec['title'], bg=COL['panel'], fg=SEVC[rec['severity']],
                 font=self.F_MB, anchor='w', justify='left').pack(fill='x', padx=16, pady=(16, 4))
        tk.Label(d, text=f"[{rec['severity'].upper()}]  ·  module: {rec['module']}  ·  {rec['time'][:19]}",
                 bg=COL['panel'], fg=COL['dim'], font=self.F_MT).pack(fill='x', padx=16)
        tk.Frame(d, bg=COL['line'], height=1).pack(fill='x', padx=16, pady=10)
        txt = tk.Text(d, bg='#060b15', fg=COL['txt'], font=self.F_MS, bd=0, wrap='word', padx=12, pady=10)
        txt.insert('end', f"DETAIL\n{rec['detail']}\n\nEVIDENCE\n{rec['evidence'] or '—'}")
        txt.config(state='disabled'); txt.pack(fill='both', expand=True, padx=16, pady=(0, 16))

    def clear_findings(self):
        self.findings = []; self.fmap = {}; self.fcount = 0
        self.sev_counts = {s: 0 for s in SEV_ORDER}
        for i in self.ftree.get_children(): self.ftree.delete(i)
        for s in SEV_ORDER: self.sev_lbls[s].config(text='0')
        self.find_count_lbl.config(text='0 findings')
        self.ops_log('warn', 'findings wiped from memory')

    def report_dict(self):
        from collections import Counter
        cnt = Counter(f['severity'] for f in self.findings)
        return {'meta': {'tool': 'RECON//NEXUS GUI', 'version': VERSION, 'author': 'empsolohk',
                         'generated': datetime.now().isoformat(), 'target': self.target},
                'summary': {s: cnt.get(s, 0) for s in SEV_ORDER},
                'findings': self.findings,
                'data': {k: v for k, v in self.info.items() if k != 'wayback'},
                'wayback_interesting': self.info.get('wayback', [])[:200]}

    def export_json(self):
        if not self.target:
            messagebox.showwarning('NO TARGET', 'Lock a target first.'); return
        p = filedialog.asksaveasfilename(defaultextension='.json',
            initialfile=f'nexus-{self.target}.json', filetypes=[('JSON', '*.json')])
        if not p: return
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(self.report_dict(), f, indent=2, ensure_ascii=False)
        self.ops_log('ok', f'report saved → {p}')

    def export_md(self):
        if not self.target:
            messagebox.showwarning('NO TARGET', 'Lock a target first.'); return
        p = filedialog.asksaveasfilename(defaultextension='.md',
            initialfile=f'nexus-{self.target}.md', filetypes=[('Markdown', '*.md')])
        if not p: return
        from collections import Counter
        cnt = Counter(f['severity'] for f in self.findings)
        md = [f'# RECON//NEXUS Report — {self.target}',
              f'_Generated {datetime.now().isoformat()} · v{VERSION} · by empsolohk_\n',
              '## Summary', '| Severity | Count |', '|---|---|']
        md += [f'| {s.upper()} | {cnt.get(s, 0)} |' for s in SEV_ORDER]
        md.append('\n## Findings\n')
        md += [f"- **[{f['severity'].upper()}]** {f['title']} — {f['detail']} `{(f['evidence'] or '')[:120]}`"
               for f in sorted(self.findings, key=lambda x: SEV_ORDER.index(x['severity']))]
        if self.info.get('subs'):
            md.append(f"\n## Subdomains ({len(self.info['subs'])})\n")
            md += [f'- {n}' for n in self.info['subs']]
        with open(p, 'w', encoding='utf-8') as f:
            f.write('\n'.join(md))
        self.ops_log('ok', f'report saved → {p}')

def main():
    app = Nexus()
    app.mainloop()

if __name__ == '__main__':
    main()