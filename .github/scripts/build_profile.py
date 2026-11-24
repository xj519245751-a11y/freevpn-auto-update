#!/usr/bin/env python3
"""Build a bounded Mihomo/Clash Meta YAML profile from public URI lists.

This checks syntax and provenance only. It does NOT prove that a public node is
safe, private, or reachable. Never put personal credentials in source feeds.
"""
from __future__ import annotations
import base64, json, os, re, time
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
        return {"name":name,"type":"ss","server":host,"port":port,"cipher":method,"password":unquote(password),"udp":True}
    raise ValueError("unsupported scheme")

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
    # Evenly sample across the combined source order to cap profile size.
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
    profile={
      "mixed-port":7890,"allow-lan":False,"mode":"rule","log-level":"warning",
      "ipv6":False,
      "proxies":proxies,
      "proxy-groups":[
        {"name":"AUTO","type":"url-test","proxies":[p["name"] for p in proxies],
         "url":"https://www.gstatic.com/generate_204","interval":300,"tolerance":100},
        {"name":"PROXY","type":"select","proxies":["AUTO"]+[p["name"] for p in proxies]},
      ],
      "rules":["MATCH,PROXY"]
    }
    OUT.mkdir(exist_ok=True)
    try:
        import yaml
    except ImportError:
        raise SystemExit("PyYAML missing")
    (OUT/"clash.yaml").write_text(yaml.safe_dump(profile,allow_unicode=True,sort_keys=False),encoding="utf-8")
    report={"generatedAt":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
            "sources":source_status,"uniqueInputLines":len(seen),"publishedNodes":len(proxies),
            "parseErrors":errors,"maxNodes":MAX_NODES,
            "warning":"Syntax-filtered public third-party nodes only; no trust or reachability guarantee."}
    (OUT/"status.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(f"Published {len(proxies)} parsed nodes; {errors} parse failures; {len(source_status)} sources checked.")
if __name__=="__main__": main()
