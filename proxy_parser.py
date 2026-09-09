#!/usr/bin/env python3
import base64, json, os, re, subprocess, tempfile, time, urllib.parse, urllib.request
from pathlib import Path

SOURCES_FILE = Path('proxy_sources.txt')
OUTPUT_FILE = Path('proxies.txt')
MAX_BYTES = 20 * 1024 * 1024
TEST_URL = os.getenv('TEST_URL', 'http://www.gstatic.com/generate_204')
TIMEOUT_MS = int(os.getenv('TEST_TIMEOUT_MS', '5000'))
PARALLEL = int(os.getenv('PARALLEL', '8'))

URI_RE = re.compile(r'(?i)\b(?:vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|socks5?|http)://[^\s<>"\']+')

def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'kafka-sub-health-test/1.0'})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('source is larger than 20 MiB')
    return data.decode('utf-8', errors='replace')

def extract_uris(text, depth=0):
    if depth > 3: return []
    found = [x.rstrip('.,;:)]}>"\'') for x in URI_RE.findall(text)]
    compact = re.sub(r'\s+', '', text)
    if depth < 3 and len(compact) >= 16 and re.fullmatch(r'[A-Za-z0-9+/=_-]+', compact):
        try:
            decoded = base64.urlsafe_b64decode(compact + '=' * (-len(compact) % 4)).decode('utf-8', errors='replace')
            if decoded != text: found.extend(extract_uris(decoded, depth + 1))
        except Exception: pass
    if depth < 2:
        try:
            found.extend(extract_uris(json.dumps(json.loads(text), ensure_ascii=False), depth + 1))
        except Exception: pass
    return found

def is_mlkem(uri):
    try:
        p = urllib.parse.urlsplit(uri.split('#',1)[0])
        q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        return any(k.lower() == 'encryption' and any(str(v).lower().startswith('mlkem768x25519plus') for v in vals) for k, vals in q.items())
    except Exception:
        return False

def q1(q, key, default=None):
    return q.get(key, [default])[0]

def truth(v): return str(v or '').lower() in ('1','true','yes','on')

def parse_uri(uri, name):
    raw = uri.split('#',1)[0]
    p = urllib.parse.urlsplit(raw)
    scheme = p.scheme.lower()
    q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    frag = urllib.parse.unquote(p.fragment)
    if scheme == 'vless':
        d = {'name': name, 'type':'vless', 'server':p.hostname, 'port':p.port, 'uuid':urllib.parse.unquote(p.username or '')}
        network = q1(q,'type','tcp')
        if network: d['network'] = network
        if truth(q1(q,'tls')) or q1(q,'security') in ('tls','reality'): d['tls'] = True
        if q1(q,'serverName'): d['servername'] = q1(q,'serverName')
        elif q1(q,'sni'): d['servername'] = q1(q,'sni')
        if q1(q,'flow'): d['flow'] = q1(q,'flow')
        if q1(q,'fp'): d['client-fingerprint'] = q1(q,'fp')
        if q1(q,'pbk'): d['reality-opts'] = {'public-key': q1(q,'pbk')}
        if q1(q,'sid'): d.setdefault('reality-opts',{})['short-id'] = q1(q,'sid')
        if q1(q,'allowInsecure') is not None: d['skip-cert-verify'] = truth(q1(q,'allowInsecure'))
        if network == 'ws':
            d['ws-opts'] = {'path': q1(q,'path','/')}
            host = q1(q,'host')
            if host: d['ws-opts']['headers'] = {'Host': host}
        elif network == 'grpc':
            d['grpc-opts'] = {'grpc-service-name': q1(q,'serviceName','')}
        elif network in ('http','h2'):
            d['http-opts'] = {'path': [q1(q,'path','/')], 'headers': {}}
        return d
    if scheme == 'trojan':
        d={'name':name,'type':'trojan','server':p.hostname,'port':p.port,'password':urllib.parse.unquote(p.username or '')}
        d['sni']=q1(q,'sni') or q1(q,'peer') or p.hostname
        d['skip-cert-verify']=truth(q1(q,'allowInsecure'))
        network=q1(q,'type')
        if network == 'ws':
            d['network']='ws'; d['ws-opts']={'path':q1(q,'path','/')}
        return d
    if scheme in ('ss','socks5','socks','http'):
        if scheme == 'ss':
            host=p.hostname; port=p.port
            user=urllib.parse.unquote(p.username or '')
            pwd=urllib.parse.unquote(p.password or '')
            if not pwd and user and ':' in user: user,pwd=user.split(':',1)
            return {'name':name,'type':'ss','server':host,'port':port,'cipher':user,'password':pwd}
        typ = 'socks5' if scheme.startswith('socks') else 'http'
        d={'name':name,'type':typ,'server':p.hostname,'port':p.port}
        if p.username: d['username']=urllib.parse.unquote(p.username)
        if p.password: d['password']=urllib.parse.unquote(p.password)
        return d
    if scheme in ('hysteria2','hy2'):
        d={'name':name,'type':'hysteria2','server':p.hostname,'port':p.port,'password':urllib.parse.unquote(p.username or '')}
        if q1(q,'sni'): d['sni']=q1(q,'sni')
        if q1(q,'insecure') is not None: d['skip-cert-verify']=truth(q1(q,'insecure'))
        if q1(q,'obfs'): d['obfs']=q1(q,'obfs'); d['obfs-password']=q1(q,'obfs-password','')
        return d
    if scheme == 'tuic':
        d={'name':name,'type':'tuic','server':p.hostname,'port':p.port,'uuid':urllib.parse.unquote(p.username or ''),'password':urllib.parse.unquote(p.password or '')}
        d['sni']=q1(q,'sni') or p.hostname
        d['skip-cert-verify']=truth(q1(q,'allowInsecure'))
        if q1(q,'congestion_control'): d['congestion-controller']=q1(q,'congestion_control')
        return d
    if scheme == 'vmess':
        payload=(p.netloc+p.path).strip()
        obj=json.loads(base64.urlsafe_b64decode(payload + '='*(-len(payload)%4)).decode('utf-8'))
        d={'name':name,'type':'vmess','server':obj.get('add'),'port':int(obj.get('port',0)),'uuid':obj.get('id'),'alterId':int(obj.get('aid',0)),'cipher':obj.get('scy') or 'auto'}
        if str(obj.get('tls','')).lower() in ('tls','true'): d['tls']=True
        if obj.get('sni'): d['servername']=obj['sni']
        net=obj.get('net','tcp')
        if net: d['network']=net
        if net=='ws': d['ws-opts']={'path':obj.get('path') or '/', 'headers':({'Host':obj['host']} if obj.get('host') else {})}
        if obj.get('host') and net!='ws': d['servername']=obj.get('host')
        return d
    raise ValueError(f'unsupported scheme: {scheme}')

def write_config(proxies, path, secret):
    # JSON is accepted by Mihomo as configuration, while output remains plain URI text.
    cfg={'mixed-port': 0, 'mode':'rule', 'allow-lan':False, 'log-level':'silent', 'external-controller':'127.0.0.1:9090', 'secret':secret, 'proxies':proxies, 'rules':['MATCH,DIRECT']}
    path.write_text(json.dumps(cfg, ensure_ascii=False), encoding='utf-8')

def api_delay(name, secret):
    url='http://127.0.0.1:9090/proxies/' + urllib.parse.quote(name, safe='') + '/delay?' + urllib.parse.urlencode({'url':TEST_URL,'timeout':TIMEOUT_MS})
    req=urllib.request.Request(url, headers={'Authorization':f'Bearer {secret}'})
    with urllib.request.urlopen(req, timeout=TIMEOUT_MS/1000+3) as r:
        data=json.loads(r.read().decode())
    return int(data.get('delay',0))

def main():
    if not SOURCES_FILE.exists(): raise SystemExit('proxy_sources.txt not found')
    sources=[x.strip() for x in SOURCES_FILE.read_text(encoding='utf-8').splitlines() if x.strip() and not x.lstrip().startswith('#')]
    unique=[]; seen=set()
    for source in sources:
        try:
            added=0
            for uri in extract_uris(fetch(source)):
                key=uri.split('#',1)[0]
                if key in seen or is_mlkem(uri): continue
                seen.add(key); unique.append(uri); added+=1
            print(f'[SOURCE] {source} -> {added} new proxy URLs')
        except Exception as e: print(f'[SOURCE ERROR] {source}: {e}')
    print(f'[TOTAL] {len(unique)} unique candidates')
    if not unique:
        OUTPUT_FILE.write_text('', encoding='utf-8'); return

    mihomo=os.getenv('MIHOMO_BIN','mihomo')
    secret='kafka-health-test'
    good=[]
    with tempfile.TemporaryDirectory() as td:
        td=Path(td); cfg=td/'config.json'
        proxies=[]; meta=[]
        for i,uri in enumerate(unique,1):
            name=f'🇨🇾 Cyprus | Кипр #{i}'
            try:
                proxies.append(parse_uri(uri,name)); meta.append((name,uri))
            except Exception as e: print(f'[PARSE FAIL] #{i}: {e}')
        if not proxies:
            OUTPUT_FILE.write_text('', encoding='utf-8'); return
        write_config(proxies,cfg,secret)
        log=td/'mihomo.log'
        proc=subprocess.Popen([mihomo,'-d',str(td),'-f',str(cfg)], stdout=log.open('wb'), stderr=subprocess.STDOUT)
        try:
            for _ in range(40):
                try:
                    urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:9090/version',headers={'Authorization':f'Bearer {secret}'}),timeout=1); break
                except Exception: time.sleep(.25)
            else: raise RuntimeError('mihomo API did not start')
            # Sequential requests are intentional: the same core handles all nodes and avoids spawning one process per proxy.
            for i,(name,uri) in enumerate(meta,1):
                try:
                    delay=api_delay(name,secret)
                    if delay > 0:
                        good.append(uri.split('#',1)[0])
                        print(f'[OK] #{i} {delay} ms')
                    else: print(f'[FAIL] #{i}')
                except Exception as e: print(f'[FAIL] #{i} {e}')
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()

    output=[]
    for i,uri in enumerate(good,1):
        label=urllib.parse.quote(f'🇨🇾 Cyprus | Кипр #{i}',safe='')
        output.append(uri+'#'+label)
    header='#profile-title: kafka health test\n#announce: только рабочие конфиги | конфигов: '+str(len(output))
    OUTPUT_FILE.write_text(header+'\n'+'\n'.join(output)+'\n',encoding='utf-8')
    print(f'[DONE] {len(output)} working proxies -> {OUTPUT_FILE}')

if __name__=='__main__': main()
