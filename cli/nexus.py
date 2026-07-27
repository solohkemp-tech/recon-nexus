#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RECON//NEXUS v3.0.0 â€” CLI Â· zero-deps Â· no API keys Â· by empsolohk"""
import argparse, json, random, re, socket, ssl, sys, threading, time, webbrowser
import urllib.request, urllib.error, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VERSION="3.0.0"
class C:
    R='\033[0m';B='\033[1m';DIM='\033[2m';RED='\033[91m';GRN='\033[92m';YLW='\033[93m';BLU='\033[94m';MAG='\033[95m';CYN='\033[96m'
    @classmethod
    def disable(cls):
        for k in ('R','B','DIM','RED','GRN','YLW','BLU','MAG','CYN'): setattr(cls,k,'')
SEVC={'critical':C.RED,'high':C.YLW,'medium':C.CYN,'low':C.GRN,'info':C.BLU}
SEV_ORDER=['critical','high','medium','low','info']
def badge(s): return f"{SEVC[s]}[{s.upper():^8}]{C.R}"
def log(m,l='info'):
    t={'info':f'{C.CYN}[*]','ok':f'{C.GRN}[+]','warn':f'{C.YLW}[!]','err':f'{C.RED}[x]','sys':f'{C.MAG}[Â·]'}[l]
    print(f"  {t}{C.R} {m}")
def hb(n):
    n=float(n)
    for u in ('B','KB','MB','GB'):
        if n<1024: return f"{n:.0f}{u}" if u=='B' else f"{n:.1f}{u}"
        n/=1024
    return f"{n:.1f}TB"

DEFAULT_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36'
DOMAIN_RE=re.compile(r'^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$',re.I)
def norm(t):
    t=t.strip().lower(); t=re.sub(r'^https?://','',t); return t.split('/')[0].split(':')[0]

def http_request(url,cfg,max_read=65536,headers=None,timeout=None):
    handlers=[]
    if cfg.get('proxy'): handlers.append(urllib.request.ProxyHandler({'http':cfg['proxy'],'https':cfg['proxy']}))
    if cfg.get('ctx'): handlers.append(urllib.request.HTTPSHandler(context=cfg['ctx']))
    opener=urllib.request.build_opener(*handlers)
    base={'User-Agent':cfg.get('ua',DEFAULT_UA),'Accept':'*/*','Connection':'close'}
    if headers: base={**base,**headers}
    req=urllib.request.Request(url,headers=base)
    try:
        r=opener.open(req,timeout=timeout or cfg.get('timeout',10)); b=r.read(max_read)
        return r.status,{k.lower():v for k,v in r.headers.items()},b,r.geturl()
    except urllib.error.HTTPError as e:
        b=b''
        try: b=e.read(max_read)
        except Exception: pass
        return e.code,{k.lower():v for k,v in e.headers.items()},b,url
    except Exception as e:
        return None,{},b'',str(e)

DOH_SERVERS=[('https://cloudflare-dns.com/dns-query?name={n}&type={t}',{'Accept':'application/dns-json'}),
             ('https://dns.google/resolve?name={n}&type={t}',{}),
             ('https://dns.quad9.net:5053/dns-query?name={n}&type={t}',{'Accept':'application/dns-json'})]
UDP_RESOLVERS=['1.1.1.1','8.8.8.8','9.9.9.9','178.22.122.100']
_QT={'A':1,'AAAA':28,'MX':15,'NS':2,'TXT':16,'SOA':6,'CAA':257,'CNAME':5}
def _dns_parse(data):
    import struct
    def name(off):
        p=[]
        while True:
            ln=data[off]
            if ln==0: off+=1; break
            if ln&0xc0==0xc0:
                pt=struct.unpack('>H',data[off:off+2])[0]&0x3fff; s,_=name(pt); p.append(s); off+=2; break
            p.append(data[off+1:off+1+ln].decode('utf-8','ignore')); off+=1+ln
        return '.'.join(p),off
    try:
        _,_,qd,an,_,_=struct.unpack('>HHHHHH',data[:12]); off=12
        for _ in range(qd): _,off=name(off); off+=4
        out=[]
        for _ in range(an):
            _,off=name(off); rt,_,_,rl=struct.unpack('>HHIH',data[off:off+10]); off+=10; rd=data[off:off+rl]
            if rt==1 and rl==4: out.append('.'.join(map(str,rd)))
            elif rt==28 and rl==16: out.append(socket.inet_ntop(socket.AF_INET6,rd))
            elif rt in (2,5,12): out.append(name(off)[0])
            elif rt==15: out.append(f'{struct.unpack(">H",rd[:2])[0]} {name(off+2)[0]}')
            elif rt==16:
                t=b''; i=0
                while i<rl: t+=rd[i+1:i+1+rd[i]]; i+=1+rd[i]
                out.append(t.decode('utf-8','ignore'))
            elif rt==6: m,o2=name(off); r,_=name(o2); out.append(f'{m} {r}')
            elif rt==257: out.append(f'{rd[2:2+rd[1]].decode()} "{rd[2+rd[1]:].decode("utf-8","ignore")}"')
            off+=rl
        return out
    except Exception: return []
def dns_udp(qn,rt,cfg):
    import struct
    qt=_QT.get(rt,1); pkt=struct.pack('>HHHHHH',random.randint(0,65535),0x0100,1,0,0,0)
    for lab in qn.rstrip('.').split('.'): pkt+=bytes([len(lab)])+lab.encode()
    pkt+=b'\x00'+struct.pack('>HH',qt,1)
    for res in UDP_RESOLVERS:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(4)
            s.sendto(pkt,(res,53)); data,_=s.recvfrom(4096); s.close()
            a=_dns_parse(data)
            if a: return a
        except Exception: continue
    return []
def doh(name,rtype,cfg):
    for tmpl,hdrs in DOH_SERVERS:
        url=tmpl.format(n=urllib.parse.quote(name),t=rtype)
        s,_,b,_=http_request(url,cfg,headers=hdrs,timeout=6)
        if s==200:
            try:
                j=json.loads(b)
                if j.get('Status',0) in (0,3): return [a.get('data','') for a in j.get('Answer',[])]
            except Exception: continue
    udp=dns_udp(name,rtype,cfg)
    if udp: return udp
    if rtype in ('A','AAAA'):
        try:
            fam=socket.AF_INET if rtype=='A' else socket.AF_INET6
            return sorted({i[4][0] for i in socket.getaddrinfo(name,None,fam,socket.SOCK_STREAM)})
        except Exception: pass
    return []

DORKS=[("FILE & DIRECTORY",[('Directory listing','intitle:"index of /" site:{t}','high'),('Exposed config','site:{t} ext:cfg OR ext:conf OR ext:ini','high'),('Exposed DB files','site:{t} ext:sql OR ext:db OR ext:mdb','critical'),('Exposed logs','site:{t} ext:log','medium'),('Backups','site:{t} ext:bak OR ext:backup OR ext:old OR ext:zip','high'),('Admin backups','inurl:admin site:{t} ext:zip OR ext:sql','critical'),('WP config','site:{t} inurl:wp-config','critical'),('.git','site:{t} inurl:".git"','critical'),('.env','site:{t} ext:env','critical'),('Private keys','site:{t} ext:pem OR ext:key "PRIVATE KEY"','critical'),('id_rsa','site:{t} intitle:"index of" "id_rsa"','critical'),('Passwords','site:{t} intitle:"index of" passwd OR shadow','critical')]),
("WEB APPLICATION",[('Login pages','site:{t} inurl:login OR inurl:signin','info'),('SQL errors','site:{t} "SQL syntax" OR "MySQL server version"','high'),('phpinfo','site:{t} intitle:"phpinfo()"','high'),('Backdoors','site:{t} inurl:shell.php OR inurl:c99 OR inurl:r57','critical'),('Open redirects','site:{t} inurl:redirect= OR inurl:return= OR inurl:url=','medium'),('Admin portals','site:{t} inurl:admin OR inurl:dashboard','info'),('Uploads','site:{t} inurl:upload.php OR inurl:uploader','high'),('Debug','site:{t} "stack trace" OR intitle:"Server Error"','medium'),('phpMyAdmin','site:{t} intitle:"phpMyAdmin"','high'),('Staging','site:{t} inurl:test OR inurl:staging OR inurl:dev.','low')]),
("INFORMATION GATHERING",[('Pastebin','site:pastebin.com "{t}"','high'),('LinkedIn','site:linkedin.com/in "{t}"','low'),('Sensitive txt','site:{t} ext:txt password OR secret','high'),('Subdomains','site:*.{t}','medium'),('crt.sh','https://crt.sh/?q=%25.{t}','info'),('GitHub','site:github.com "{t}"','medium'),('Emails','site:{t} "@{t}"','medium')]),
("CLOUD & INFRA",[('HackerOne','site:hackerone.com "{t}"','info'),('Shodan','https://www.shodan.io/search?query={t}','info'),('Jenkins','site:{t} intitle:"Dashboard [Jenkins]"','high'),('Kibana','site:{t} intitle:"Kibana"','high'),('S3 buckets','site:{t}.s3.amazonaws.com','high'),('Kubernetes','site:{t} intitle:"Kubernetes Dashboard"','critical'),('Docker API','site:{t} inurl:":2375"','critical'),('MongoDB','site:{t} inurl:":27017"','critical'),('Jupyter','site:{t} intitle:"Jupyter Notebook"','high'),('Grafana','site:{t} intitle:"Grafana"','medium')]),
("API & DEV",[('GitHub secrets','site:github.com "{t}" password OR secret OR api_key','critical'),('GraphQL','site:{t} inurl:graphql','high'),('API keys','site:{t} "api_key" OR "secret_key" OR "access_token"','critical'),('Spring actuator','site:{t} inurl:actuator','high'),('Actuator env','site:{t} inurl:actuator/env','critical'),('Env secrets','site:{t} ext:env DB_PASSWORD OR API_KEY','critical'),('Swagger','site:{t} inurl:swagger OR inurl:api-docs','medium'),('SQLi URL','site:{t} inurl:.php?id=','high')]),
("MODERN PLATFORMS",[('n8n','site:{t} intitle:"n8n"','high'),('Ray','site:{t} intitle:"Ray Dashboard"','critical'),('Argo CD','site:{t} intitle:"Argo CD"','high'),('Portainer','site:{t} intitle:"Portainer"','high'),('Weave Scope','site:{t} intitle:"Weave Scope"','critical'),('K8s API','site:{t} inurl:"/api/v1/namespaces"','critical'),('Mongo Express','site:{t} intitle:"Mongo Express"','critical'),('Laravel Ignition','site:{t} inurl:"_ignition/health-check"','critical'),('vCenter','site:{t} intitle:"vCenter"','critical'),('Zabbix','site:{t} intitle:"Zabbix"','high')]),
("ARCHIVES",[('crossdomain','site:{t} inurl:crossdomain.xml','medium'),('Wayback','https://web.archive.org/web/*/{t}','info'),('Downloads','site:{t} ext:apk OR ext:exe OR ext:msi','medium'),('/etc','site:{t} inurl:"/etc/"','high'),('VirusTotal','https://www.virustotal.com/gui/domain/{t}','info'),('urlscan','https://urlscan.io/domain/{t}','info')])]
N_DORKS=sum(len(d[1]) for d in DORKS)
ENGINES={'google':'https://www.google.com/search?q={}','bing':'https://www.bing.com/search?q={}','duckduckgo':'https://duckduckgo.com/?q={}','yandex':'https://yandex.com/search/?text={}','startpage':'https://www.startpage.com/sp/search?query={}'}

PROBES=[("/.git/config","critical","Git repo"),("/.env","critical","Env secrets"),("/.env.production","critical","Prod env"),("/.aws/credentials","critical","AWS creds"),("/id_rsa","critical","Private key"),("/wp-config.php.bak","critical","WP config bak"),("/db.sql","critical","SQL dump"),("/actuator/env","critical","Spring env"),("/actuator/heapdump","critical","Spring heap"),("/api/v1/namespaces","critical","K8s API"),("/v2/_catalog","critical","Docker registry"),("/_ignition/health-check","critical","Laravel RCE"),("/swagger.json","high","Swagger"),("/openapi.json","high","OpenAPI"),("/graphql","high","GraphQL"),("/phpinfo.php","high","phpinfo"),("/server-status","high","Apache status"),("/console","high","Werkzeug console"),("/debug/pprof","high","Go pprof"),("/elmah.axd","high","ELMAH"),("/.htaccess","high","Apache cfg"),("/web.config","high","IIS cfg"),("/backup.zip","high","Backup"),("/.npmrc","high","npm token"),("/_cat/indices","high","Elastic"),("/metrics","high","Prometheus"),("/adminer.php","high","Adminer"),("/wp-content/debug.log","high","WP debug"),("/storage/logs/laravel.log","high","Laravel log"),("/keycloak/","high","Keycloak"),("/.DS_Store","medium","DS_Store"),("/.well-known/openid-configuration","medium","OIDC"),("/crossdomain.xml","medium","Flash policy"),("/package.json","medium","Node manifest"),("/Dockerfile","medium","Dockerfile"),("/robots.txt","info","Robots"),("/sitemap.xml","info","Sitemap"),("/.well-known/security.txt","info","security.txt"),("/wp-login.php","info","WP login"),("/admin/","info","Admin"),("/health","info","Health")]
WORDLIST="""www mail ftp admin dev api staging test blog shop app portal vpn git jira jenkins wiki docs status cdn static img media old new beta demo sandbox internal db mysql postgres redis elastic kibana grafana prometheus vault k8s docker registry s3 backup files cms wp webmail smtp mx support help login auth sso id mobile m secure my account billing pay gateway ws api2 v1 v2 qa uat origin edge cache images store crm hr intranet chat monitor ops ci cd deploy sonar ansible terraform consul nomad etcd data bi analytics logs kafka airflow jupyter sentry keycloak gitea gitlab nexus harbor argo traefik kong""".split()
INTERESTING_RE=re.compile(r'(admin|config|backup|\.env|\.git|\.sql|\.zip|\.bak|token|secret|password|upload|internal|staging|debug|phpinfo|wp-config|\.key|\.pem|actuator|swagger|graphql|\.json|\.yaml|\.log)',re.I)
TECH_SIGS=[('h','server',r'nginx[/ ]?([\d.]+)?','Nginx'),('h','server',r'Apache[/ ]?([\d.]+)?','Apache'),('h','server',r'Microsoft-IIS[/ ]?([\d.]+)?','IIS'),('h','x-powered-by',r'PHP[/ ]?([\d.]+)?','PHP'),('h','x-powered-by',r'ASP\.NET','ASP.NET'),('h','cf-ray',r'.*','Cloudflare'),('h','set-cookie',r'laravel_session','Laravel'),('h','set-cookie',r'PHPSESSID','PHP'),('b','',r'wp-content/','WordPress'),('b','',r'__NEXT_DATA__','Next.js'),('b','',r'ng-version','Angular'),('b','',r'jquery[.-]([\d.]+)?','jQuery')]

def mod_dns(d,em,cfg):
    log('resolving DNS (DoH + UDP fallback) â€¦','sys')
    recs={t:doh(d,t,cfg) for t in ('A','AAAA','MX','NS','TXT','SOA','CAA')}; recs['DMARC']=doh('_dmarc.'+d,'TXT',cfg)
    for t,v in recs.items():
        if v: print(f"  {C.B}{t:<7}{C.R}",end='')
        for x in v[:6]: print(f"\n          {C.DIM}{str(x)[:88]}{C.R}",end='')
        if v: print()
    if not any('v=spf1' in str(x) for x in recs['TXT']): em.append(('dns','SPF missing','info','no SPF TXT'))
    if not recs['DMARC']: em.append(('dns','DMARC missing','info','no _dmarc TXT'))
def mod_cert(d,em,cfg):
    log('extracting TLS certificate â€¦','sys')
    try:
        with socket.create_connection((d,443),timeout=cfg['timeout']) as sock:
            with cfg['ctx'].wrap_socket(sock,server_hostname=d) as ss:
                cert,proto,cipher=ss.getpeercert(),ss.version(),ss.cipher()[0]
        sans=[v for k,v in cert.get('subjectAltName',()) if k=='DNS']
        days=int((ssl.cert_time_to_seconds(cert['notAfter'])-time.time())/86400)
        issuer=dict(x[0] for x in cert.get('issuer',())).get('organizationName','?')
        print(f"  {C.DIM}issuer{C.R}  {issuer}\n  {C.DIM}SANs{C.R}    {len(sans)}: {', '.join(sans[:10])}\n  {C.DIM}expiry{C.R}  {cert['notAfter']} ({days}d)\n  {C.DIM}proto{C.R}   {proto} Â· {cipher}")
        if days<14: em.append(('cert','Cert expiring soon','medium',f'{days} days'))
        em.append(('cert',f'{len(sans)} SANs','info',', '.join(sans[:8])))
    except Exception as e: log(f'cert failed â†’ {e}','err')
def mod_subs(d,em,cfg):
    log('querying crt.sh CT logs â€¦','sys'); subs={}
    st,_,body,_=http_request(f'https://crt.sh/?q=%25.{d}&output=json',cfg,timeout=30)
    if st==200:
        try:
            for e in json.loads(body):
                for f in ('name_value','common_name'):
                    for n in str(e.get(f,'')).split('\n'):
                        n=n.strip().lower().lstrip('*.')
                        if n.endswith(d) and DOMAIN_RE.match(n): subs.setdefault(n,set()).add('CT')
        except Exception: pass
    log(f'CT â†’ {len(subs)} Â· DoH brute â†’ {len(WORDLIST)}','sys')
    def chk(w):
        r=doh(f'{w}.{d}','A',cfg); return (f'{w}.{d}',r)
    with ThreadPoolExecutor(max_workers=25) as ex:
        for n,r in ex.map(chk,WORDLIST):
            if r: subs.setdefault(n,set()).add('DNS')
    names=sorted(subs)
    for n in names: print(f"  {C.GRN}â–¸{C.R} {n}")
    log(f'{len(names)} subdomains','ok'); em.append(('subs',f'{len(names)} subdomains','info',', '.join(names[:10])))
def mod_wayback(d,em,cfg):
    log('mining Wayback CDX â€¦','sys')
    st,_,body,_=http_request(f'https://web.archive.org/cdx/search/cdx?url=*.{d}*&output=json&fl=original&collapse=urlkey&limit=2500',cfg,timeout=30)
    if st!=200: log('wayback unavailable','err'); return
    try: rows=json.loads(body)[1:]
    except Exception: rows=[]
    urls=[r[0] for r in rows]; hits=[u for u in urls if INTERESTING_RE.search(u)]
    log(f'{len(urls)} archived Â· {len(hits)} interesting','ok')
    for u in hits[:20]: print(f"  {C.DIM}{u[:108]}{C.R}")
    if hits: em.append(('wayback',f'{len(hits)} suspicious URLs','info','; '.join(hits[:6])))
def mod_headers(d,em,cfg):
    log('auditing security headers â€¦','sys')
    st,h,body,final=http_request(f'https://{d}/',cfg)
    if st is None: st,h,body,final=http_request(f'http://{d}/',cfg)
    if st is None: log(f'unreachable â†’ {final}','err'); return
    def miss(x,s,t): 
        if x not in h: em.append(('headers',t,s,f'missing {x}'))
    miss('strict-transport-security','medium','HSTS missing'); miss('content-security-policy','low','CSP missing')
    miss('x-content-type-options','low','XCTO missing'); miss('x-frame-options','low','XFO missing')
    if h.get('access-control-allow-origin')=='*': em.append(('headers','Wildcard CORS','medium','ACAO: *'))
    for ck in h.get('set-cookie','').split(','):
        nm=ck.split('=')[0].strip()
        if nm and 'secure' not in ck.lower(): em.append(('headers',f'Cookie {nm} w/o Secure','medium',nm))
    for lk in ('server','x-powered-by'):
        if h.get(lk): em.append(('headers',f'Disclosure ({lk})','low',h[lk]))
    text=body.decode('utf-8','ignore'); tech=[]
    for k,key,rx,nm in TECH_SIGS:
        hay=h.get(key,'') if k=='h' else text
        m=re.search(rx,hay,re.I)
        if m: tech.append(nm+(f' {m.group(1)}' if m.lastindex else ''))
    tech=list(dict.fromkeys(tech))
    print(f"  {C.DIM}response{C.R} {st} â†’ {final[:70]}\n  {C.DIM}tech{C.R}     {', '.join(tech) or 'â€”'}")
def mod_probe(d,em,cfg,threads=25):
    log(f'probing {len(PROBES)} paths Â· {threads} threads â€¦','sys'); base=f'https://{d}'
    st0,_,_,_=http_request(base+'/',cfg,max_read=1024)
    if st0 is None: base=f'http://{d}'; st0,_,_,_=http_request(base+'/',cfg,max_read=1024)
    if st0 is None: log('unreachable','err'); return
    rnd=''.join(random.choices('abcdef0123456789',k=14)); bst,_,bb,_=http_request(f'{base}/nx-{rnd}',cfg,max_read=65536)
    bl=len(bb) if bst is not None else None; hits=[]
    def one(item):
        path,sev,label=item; st,hh,body,_=http_request(base+path,cfg,max_read=65536)
        if st is None or st==404: return None
        if bl is not None and st in (200,403) and abs(len(body)-bl)<=32: return None
        if st in (200,206) and len(body)==0: return None
        return (path,sev,label,st,len(body),hh.get('location',''))
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(one,PROBES):
            if r: hits.append(r)
    hits.sort(key=lambda x:(SEV_ORDER.index(x[1]),-x[4]))
    for path,sev,label,st,size,loc in hits:
        print(f"  {badge(sev)} {st} {path:<36} {C.DIM}{hb(size)}{C.R}"+(f" {C.MAG}â†’ {loc[:36]}{C.R}" if loc else ''))
        em.append(('probe',f'{label} â†’ {path}',sev if st in (200,206,401) else 'info',f'{st} Â· {hb(size)}'))
    log(f'{len(hits)} live vectors','ok' if hits else 'info')
def mod_passive(d,em,cfg):
    for i,(n,fn) in enumerate((('dns',mod_dns),('cert',mod_cert),('subs',mod_subs),('wayback',mod_wayback')),1):
        log(f'phase {i}/4 â†’ {n.upper()}','sys')
        try: fn(d,em,cfg)
        except Exception as e: log(f'{n} failed â†’ {e}','err')
def mod_full(d,em,cfg):
    mod_passive(d,em,cfg)
    for i,(n,fn) in enumerate((('headers',mod_headers),('probe',mod_probe)),5):
        log(f'phase {i}/6 â†’ {n.upper()}','sys')
        try: fn(d,em,cfg)
        except Exception as e: log(f'{n} failed â†’ {e}','err')

def report(d,em,args):
    from collections import Counter
    cnt=Counter(f[2] for f in em)
    print(f"\n  {C.B}{C.CYN}â”â” MISSION DEBRIEF â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”{C.R}")
    for s in SEV_ORDER:
        n=cnt.get(s,0); print(f"  {badge(s)} {SEVC[s]}{'â–ˆ'*min(n,40)}{C.R} {C.B}{n}{C.R}")
    for f in sorted(em,key=lambda x:SEV_ORDER.index(x[2]))[:60]:
        print(f"  {badge(f[2])} {C.B}{f[1]}{C.R} {C.DIM}Â· {f[0]} Â· {f[3][:60]}{C.R}")
    if args.output:
        stamp=datetime.now().strftime('%Y%m%d-%H%M%S')
        rep={'meta':{'tool':'RECON//NEXUS','version':VERSION,'author':'empsolohk','generated':datetime.now().isoformat(),'target':d},'summary':{s:cnt.get(s,0) for s in SEV_ORDER},'findings':[{'module':m,'title':t,'severity':s,'detail':dt} for m,t,s,dt in em]}
        jf=f"{args.output}-{d}-{stamp}.json"
        with open(jf,'w',encoding='utf-8') as f: json.dump(rep,f,indent=2,ensure_ascii=False)
        log(f'report â†’ {jf}','ok')

def ensure_auth(yes):
    if yes: return True
    print(f"  {C.YLW}â•­â”€ Active scanning without written authorization is illegal. â•®\n  â•°â”€ Only proceed on targets you own or are contracted to test.{C.R}")
    try: a=input(f"\n  {C.YLW}â–¸ I have authorization [yes/N]: {C.R}").strip().lower()
    except (EOFError,KeyboardInterrupt): return False
    return a in ('y','yes')

def main():
    p=argparse.ArgumentParser(prog='nexus',description='RECON//NEXUS CLI Â· by empsolohk',epilog='by empsolohk Â· authorized targets only')
    p.add_argument('cmd',choices=['full','passive','dns','cert','subs','wayback','headers','probe','dorks'])
    p.add_argument('domain',nargs='?')
    p.add_argument('--threads',type=int,default=25); p.add_argument('--timeout',type=int,default=10)
    p.add_argument('--proxy',default=None); p.add_argument('--ua',default=None)
    p.add_argument('--insecure',action='store_true'); p.add_argument('--no-color',action='store_true')
    p.add_argument('-o','--output',default=None); p.add_argument('-y','--yes',action='store_true')
    p.add_argument('-s','--severity',default=None,choices=SEV_ORDER)
    p.add_argument('-e','--engine',default='google',choices=list(ENGINES))
    p.add_argument('--open',action='store_true'); p.add_argument('--limit',type=int,default=8)
    args=p.parse_args()
    if args.no_color or not sys.stdout.isatty(): C.disable()
    print(f"\n  {C.GRN}â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„â–„{C.R}\n  {C.GRN}â–ˆ{C.R} {C.B}RECON//NEXUS{C.R} v{VERSION} Â· {N_DORKS} payloads Â· by empsolohk\n  {C.GRN}â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€â–€{C.R}\n")
    cfg={'timeout':args.timeout,'proxy':args.proxy,'ua':args.ua or DEFAULT_UA,'ctx':ssl._create_unverified_context() if args.insecure else ssl.create_default_context()}
    if args.cmd=='dorks':
        d=norm(args.domain) if args.domain else None; opened=0; total=0
        for cat,dorks in DORKS:
            rows=[x for x in dorks if not args.severity or x[2]==args.severity]
            if not rows: continue
            print(f"\n  {C.B}{C.CYN}â”Œâ”€ {cat}{C.R} {C.CYN}{'â”'*max(2,38-len(cat))}{C.R}")
            for label,q,sev in rows:
                total+=1; print(f"  {badge(sev)} {label:<22} {C.DIM}{q.replace('{t}',d or '{TARGET}')[:80]}{C.R}")
                if args.open and d and opened<args.limit:
                    webbrowser.open((q if q.startswith('http') else ENGINES[args.engine].format(urllib.parse.quote(q.replace('{t}',d)))),new=2); opened+=1; time.sleep(1.4)
        log(f'{total} payloads','ok'); return
    if not args.domain: log('domain required','err'); sys.exit(1)
    d=norm(args.domain)
    if not DOMAIN_RE.match(d): log(f'invalid domain â†’ {d}','err'); sys.exit(1)
    em=[]
    active={'full','headers','probe'}
    if args.cmd in active and not ensure_auth(args.yes): log('blocked â€” no authorization','warn'); return
    {'full':mod_full,'passive':mod_passive,'dns':mod_dns,'cert':mod_cert,'subs':mod_subs,'wayback':mod_wayback,'headers':mod_headers,'probe':mod_probe}[args.cmd](d,em,cfg)
    report(d,em,args)
    print(f"\n  {C.DIM}â•°â”€ RECON//NEXUS v{VERSION} Â· by empsolohk Â· authorized use only{C.R}\n")

if __name__=='__main__':
    try: main()
    except KeyboardInterrupt: print(f"\n  {C.YLW}[!] aborted{C.R}"); sys.exit(130)