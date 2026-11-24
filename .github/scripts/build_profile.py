#!/usr/bin/env python3
"""Build a bounded Mihomo/Clash Meta YAML profile from public URI lists.

This checks syntax and provenance only. It does NOT prove that a public node is
safe, private, or reachable. Never put personal credentials in source feeds.
"""
from __future__ import annotations
import base64, json, os, re, time, subprocess, tempfile, shutil, concurrent.futures
from urllib.parse import urlsplit, parse_qs, unquote
from urllib.request import Request, urlopen
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "dist"
MAX_NODES = int(os.getenv("MAX_NODES", "250"))
TIMEOUT = 18
SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://")
MIRROR = "https://raw.githubusercontent.com/aneek0/goida-vpn-configs/refs/heads/main/githubmirror"
IG = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/"
SOURCES = [f"{MIRROR}/{i}.txt" for i in range(1, 27)] + [
    IG + "BLACK_SS%2BAll_RUS.txt", IG + "BLACK_VLESS_RUS.txt",
    IG + "BLACK_VLESS_RUS_mobile.txt", IG + "Vless-Reality-White-Lists-Rus-Mobile.txt",
    IG + "WHITE-CIDR-RU-all.txt", IG + "WHITE-CIDR-RU-checked.txt",
    IG + "WHITE-SNI-RU-all.txt",
]

def get(url):
    req = Request(url, headers={"User-Agent": "freevpn-auto-update/1.0"})
    with urlopen(req, timeout=TIMEOUT) as r:
        return r.read().decode("utf-8", "replace")

def dec64(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode()).decode("utf-8", "replace")

def clean_name(s, fallback):
    s = unquote(s or fallback).strip()
    return (s[:55] or fallback).replace("\n", " ")

def parse_uri(line, idx):
    line = line.strip()
    if line.startswith("vmess://"):
        raw = line[8:].split("#", 1)[0]
        obj = json.loads(dec64(raw))
        p = {"name": clean_name(line.split("#",1)[1] if "#" in line else "", f"vmess-{idx}"),
             "type":"vmess", "server":obj["add"], "port":int(obj["port"]),
             "uuid":obj["id"], "alterId":int(obj.get("aid",0)), "cipher":obj.get("scy","auto"),
             "udp":True}
        net = obj.get("net","tcp")
        if net == "ws":
            p["network"]="ws"; p["ws-opts"]={"path":obj.get("path") or "/", "headers":{"Host":obj.get("host") or obj["add"]}}
        elif net == "grpc":
            p["network"]="grpc"; p["grpc-opts"]={"grpc-service-name":obj.get("path","")}
        if obj.get("tls") == "tls":
            p["tls"]=True
            if obj.get("sni"): p["servername"]=obj["sni"]
        return p
    u = urlsplit(line)
    q = parse_qs(u.query)
    name = clean_name(u.fragment, f"{u.scheme}-{idx}")
    host, port = u.hostname, u.port
    if not host or not port: raise ValueError("missing host/port")
    if u.scheme == "vless":
        p={"name":name,"type":"vless","server":host,"port":port,"uuid":unquote(u.username or ""),"udp":True}
        sec=(q.get("security",[""])[0])
        if sec in ("tls","reality"):
            p["tls"]=True
            sni=q.get("sni",q.get("servername",[""]))[0]
            if sni: p["servername"]=sni
            if sec=="reality":
                p["reality-opts"]={"public-key":q.get("pbk",[""])[0],"short-id":q.get("sid",[""])[0]}
            fp=q.get("fp",[""])[0]
            if fp: p["client-fingerprint"]=fp
        flow=q.get("flow",[""])[0]
        if flow: p["flow"]=flow
        net=q.get("type",["tcp"])[0]
        if net=="ws":
            p["network"]="ws"; p["ws-opts"]={"path":q.get("path",["/"])[0],"headers":{"Host":q.get("host",[host])[0]}}
        elif net=="grpc":
            p["network"]="grpc"; p["grpc-opts"]={"grpc-service-name":q.get("serviceName",[""])[0]}
        return p
    if u.scheme == "trojan":
        p={"name":name,"type":"trojan","server":host,"port":port,"password":unquote(u.username or ""),"udp":True}
        sni=q.get("sni",[""])[0]
        if sni: p["sni"]=sni
        if q.get("type",[""])[0]=="ws":
            p["network"]="ws"; p["ws-opts"]={"path":q.get("path",["/"])[0],"headers":{"Host":q.get("host",[host])[0]}}
        return p
    if u.scheme in ("hy2","hysteria2"):
        p={"name":name,"type":"hysteria2","server":host,"port":port,"password":unquote(u.username or ""),"udp":True}
        sni=q.get("sni",[""])[0]
        if sni: p["sni"]=sni
        obfs=q.get("obfs",[""])[0]
        if obfs: p["obfs"]=obfs; p["obfs-password"]=q.get("obfs-password",[""])[0]
        return p
    if u.scheme == "ss":
        # SIP002 URI: ss://userinfo@host:port#name; legacy base64 form is decoded.
        user=u.username or ""
        password=u.password
        if password is None:
            decoded=dec64(u.netloc.split("@",1)[0])
            method, password = decoded.split(":",1)
        else:
            method=dec64(user) if ":" not in user else user
            if ":" in method: method,password=method.split(":",1)
        # Reject malformed/unknown cipher labels from noisy public feeds.
        allowed = {"aes-128-gcm","aes-192-gcm","aes-256-gcm","chacha20-ietf-poly1305",
                   "2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm",
                   "aes-128-cfb","aes-192-cfb","aes-256-cfb","chacha20-ietf",
                   "xchacha20-ietf-poly1305"}
        if method.lower() not in allowed or not password:
            raise ValueError("unsupported or malformed SS cipher/password")
        return {"name":name,"type":"ss","server":host,"port":port,"cipher":method.lower(),"password":unquote(password),"udp":True}
    raise ValueError("unsupported scheme")

def api_delay(name, url, timeout_ms=7000):
    from urllib.parse import quote
    endpoint = f"http://127.0.0.1:9090/proxies/{quote(name, safe='')}/delay?url={quote(url, safe='')}&timeout={timeout_ms}"
    req = Request(endpoint, headers={"Authorization": "Bearer"})
    with urlopen(req, timeout=(timeout_ms / 1000) + 5) as r:
        data = json.loads(r.read().decode("utf-8"))
    delay = int(data.get("delay", 0))
    if delay <= 0:
        raise ValueError("invalid delay")
    return delay

def test_one(proxy, urls):
    errors = []
    for url in urls:
        try:
            return {"name": proxy["name"], "delay": api_delay(proxy["name"], url), "testUrl": url}
        except Exception as e:
            errors.append(type(e).__name__)
    return {"name": proxy["name"], "delay": None, "error": ",".join(errors)}

def main():
    all_lines=[]; source_status=[]
    for url in SOURCES:
        try:
            body=get(url)
            lines=[x.strip() for x in body.splitlines() if x.strip().startswith(SCHEMES)]
            all_lines.extend(lines)
            source_status.append({"url":url,"status":"ok","entries":len(lines)})
        except Exception as e:
            source_status.append({"url":url,"status":"unavailable","error":type(e).__name__})
    seen=set(); candidates=[]
    for line in all_lines:
        if line not in seen:
            seen.add(line); candidates.append(line)
    proxies=[]; names=set(); errors=0
    if len(candidates)>MAX_NODES:
        step=len(candidates)/MAX_NODES
        candidates=[candidates[int(i*step)] for i in range(MAX_NODES)]
    for i,line in enumerate(candidates,1):
        try:
            p=parse_uri(line,i)
            base=p["name"]; n=base; k=2
            while n in names:
                n=f"{base[:48]}-{k}"; k+=1
            p["name"]=n; names.add(n); proxies.append(p)
        except Exception:
            errors+=1
    if not proxies:
        raise SystemExit("No valid nodes parsed; refusing to publish an empty profile")

    mihomo = os.getenv("MIHOMO_PATH", "mihomo")
    if not shutil.which(mihomo):
        raise SystemExit("Mihomo binary not found; refusing to publish untested nodes")

    work = tempfile.mkdtemp(prefix="mihomo-health-")
    proc = None
    try:
        test_config = {
            "mixed-port": 17890, "allow-lan": False, "mode": "rule",
            "log-level": "error", "ipv6": False,
            "external-controller": "127.0.0.1:9090",
            "proxies": proxies, "rules": ["MATCH,DIRECT"]
        }
        import yaml
        config_path = os.path.join(work, "config.yaml")
        with open(config_path, "w", encoding="utf-8") as fp:
            yaml.safe_dump(test_config, fp, allow_unicode=True, sort_keys=False)
        log_path = os.path.join(work, "mihomo.log")
        log_file = open(log_path, "w", encoding="utf-8")
        proc = subprocess.Popen([mihomo, "-d", work, "-f", config_path],
                                stdout=log_file, stderr=subprocess.STDOUT)
        ready = False
        for _ in range(30):
            if proc.poll() is not None:
                break
            try:
                with urlopen("http://127.0.0.1:9090/version", timeout=1) as r:
                    if r.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(1)
        if not ready:
            log_file.close()
            tail = open(log_path, encoding="utf-8", errors="replace").read()[-3000:]
            raise SystemExit("Mihomo failed to start; no nodes published. " + tail[-1000:])

        test_urls = [
            os.getenv("TEST_URL_PRIMARY", "https://www.gstatic.com/generate_204"),
            os.getenv("TEST_URL_FALLBACK", "https://cp.cloudflare.com/generate_204")
        ]
        results=[]
        workers=max(4, min(24, int(os.getenv("TEST_WORKERS", "16"))))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures=[pool.submit(test_one, p, test_urls) for p in proxies]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        by_name={r["name"]:r for r in results}
        good=[p for p in proxies if by_name.get(p["name"],{}).get("delay") is not None]
        good.sort(key=lambda p: by_name[p["name"]]["delay"])
        # Keep only nodes that completed a real proxied HTTP request; never fall back
        # to publishing syntax-only candidates.
        if not good:
            raise SystemExit("No nodes passed live proxy tests; existing published subscription is left untouched")
        max_publish=int(os.getenv("MAX_PUBLISH", "100"))
        good=good[:max_publish]
        profile={
          "mixed-port":7890,"allow-lan":False,"mode":"rule","log-level":"warning",
          "ipv6":False,
          "proxies":good,
          "proxy-groups":[
            {"name":"AUTO","type":"url-test","proxies":[p["name"] for p in good],
             "url":test_urls[0],"interval":300,"tolerance":100},
            {"name":"PROXY","type":"select","proxies":["AUTO"]+[p["name"] for p in good]},
          ],
          "rules":["MATCH,PROXY"]
        }
        OUT.mkdir(exist_ok=True)
        (OUT/"clash.yaml").write_text(yaml.safe_dump(profile,allow_unicode=True,sort_keys=False),encoding="utf-8")
        delays=[by_name[p["name"]]["delay"] for p in good]
        report={"generatedAt":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
                "sources":source_status,"uniqueInputLines":len(seen),
                "parsedCandidates":len(proxies),"parseErrors":errors,
                "testedNodes":len(results),"reachableNodes":len(results)-sum(1 for r in results if r["delay"] is None),
                "publishedNodes":len(good),"maxNodes":MAX_NODES,
                "maxPublish":max_publish,"testUrls":test_urls,
                "latencyMs":{"min":min(delays),"median":sorted(delays)[len(delays)//2],"max":max(delays)},
                "topNodes":[{"name":p["name"],"delayMs":by_name[p["name"]]["delay"]} for p in good[:20]],
                "warning":"Public third-party nodes are untrusted. Tests run from GitHub Actions and do not guarantee reachability or speed from a user's device."}
        (OUT/"status.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        print(f"Live-tested {len(results)} nodes; {len(good)} passed and published.")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()
        shutil.rmtree(work, ignore_errors=True)

if __name__=="__main__": main()
