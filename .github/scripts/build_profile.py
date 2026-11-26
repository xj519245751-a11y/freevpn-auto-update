#!/usr/bin/env python3
"""Build a bounded Mihomo/Clash Meta YAML profile from public URI lists.

This checks syntax and provenance only. It does NOT prove that a public node is
safe, private, or reachable. Never put personal credentials in source feeds.
"""
from __future__ import annotations
import base64, json, os, re, time, subprocess, tempfile, shutil, concurrent.futures, uuid
from urllib.parse import urlsplit, parse_qs, unquote
from urllib.request import Request, urlopen
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "dist"
MAX_NODES = int(os.getenv("MAX_NODES", "250"))
MIN_SUCCESS_CHECKS = int(os.getenv("MIN_SUCCESS_CHECKS", "4"))
TIMEOUT = 18
SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://")
MIRROR = "https://raw.githubusercontent.com/aneek0/goida-vpn-configs/refs/heads/main/githubmirror"
IG = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/"
RADAR = "https://radarhub.top/v2ray.txt"
SOURCES = [f"{MIRROR}/{i}.txt" for i in range(1, 27)] + [RADAR,
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

def extract_feed_lines(body):
    lines = [x.strip() for x in body.splitlines() if x.strip().startswith(SCHEMES)]
    if lines:
        return lines
    # Radar publishes a Base64-encoded V2Ray subscription.
    compact = "".join(body.split())
    if compact:
        try:
            decoded = dec64(compact)
            return [x.strip() for x in decoded.splitlines() if x.strip().startswith(SCHEMES)]
        except Exception:
            pass
    return []

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
        if obfs:
            obfs_password=q.get("obfs-password",[""])[0]
            if not obfs_password:
                raise ValueError("missing Hysteria2 obfs password")
            p["obfs"]=obfs
            p["obfs-password"]=obfs_password
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
    with urlopen(endpoint, timeout=(timeout_ms / 1000) + 5) as r:
        data = json.loads(r.read().decode("utf-8"))
    delay = int(data.get("delay", 0))
    if delay <= 0:
        raise ValueError("invalid delay")
    return delay

def test_one(proxy, urls, rounds=3):
    """Run repeated checks against every probe URL; tolerate isolated endpoint failures."""
    samples = []
    successes_by_url = {url: 0 for url in urls}
    valid = []
    for round_no in range(rounds):
        round_delays = []
        for url in urls:
            try:
                delay = api_delay(proxy["name"], url, timeout_ms=8000)
                round_delays.append(delay)
                valid.append(delay)
                successes_by_url[url] += 1
            except Exception:
                round_delays.append(None)
        samples.append(round_delays)
        if round_no + 1 < rounds:
            time.sleep(2)
    # Require at least MIN_SUCCESS_CHECKS successes and at least one pass per endpoint.
    stable = (len(valid) >= MIN_SUCCESS_CHECKS
              and all(count >= 1 for count in successes_by_url.values()))
    return {"name": proxy["name"], "delay": int(sorted(valid)[len(valid)//2]) if valid else None,
            "roundSamples": samples, "successesByUrl": successes_by_url,
            "passedChecks": len(valid), "requiredChecks": rounds * len(urls), "stable": stable}

def download_probe(proxy_name, url, timeout_seconds=20):
    """Measure a small proxied download through the local Mihomo mixed port."""
    from urllib.parse import quote
    endpoint = f"http://127.0.0.1:9090/proxies/PROBE"
    payload = json.dumps({"name": proxy_name}).encode("utf-8")
    req = Request(endpoint, data=payload, headers={"Content-Type": "application/json"}, method="PUT")
    with urlopen(req, timeout=5) as response:
        if response.status not in (200, 204):
            raise RuntimeError("Mihomo proxy selection failed")
    probe_url = os.getenv("SPEED_TEST_URL", "https://speed.cloudflare.com/__down?bytes=524288")
    started = time.monotonic()
    handlers = [__import__("urllib.request", fromlist=["ProxyHandler"]).ProxyHandler({
        "http": "http://127.0.0.1:17890", "https": "http://127.0.0.1:17890"
    })]
    opener = __import__("urllib.request", fromlist=["build_opener"]).build_opener(*handlers)
    req = Request(probe_url, headers={"User-Agent": "freevpn-auto-update-speedcheck/2.2"})
    total = 0
    with opener.open(req, timeout=timeout_seconds) as response:
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
    elapsed = max(time.monotonic() - started, 0.001)
    if total < 262144:
        raise RuntimeError("download sample too small")
    return {"bytes": total, "durationMs": int(elapsed * 1000),
            "throughputMbps": round(total * 8 / elapsed / 1_000_000, 3)}

def main():
    source_buckets=[]; source_status=[]; unique_input_lines=set()
    for url in SOURCES:
        try:
            body=get(url)
            lines=extract_feed_lines(body)
            bucket=[]
            for line in lines:
                if line not in unique_input_lines:
                    unique_input_lines.add(line)
                    bucket.append(line)
            source_buckets.append(bucket)
            source_status.append({"url":url,"status":"ok","entries":len(lines),
                                  "uniqueEntries":len(bucket)})
        except Exception as e:
            source_buckets.append([])
            source_status.append({"url":url,"status":"unavailable","error":type(e).__name__})
    # Round-robin across sources so one huge feed cannot monopolize the candidate budget.
    candidates=[]; positions=[0]*len(source_buckets)
    while len(candidates)<MAX_NODES:
        added=False
        for i,bucket in enumerate(source_buckets):
            if positions[i] < len(bucket) and len(candidates)<MAX_NODES:
                candidates.append(bucket[positions[i]])
                positions[i]+=1
                added=True
        if not added:
            break
    seen=unique_input_lines
    proxies=[]; names=set(); errors=0
    for i,line in enumerate(candidates,1):
        try:
            p=parse_uri(line,i)
            if not p.get("server") or not (1 <= int(p.get("port", 0)) <= 65535):
                raise ValueError("invalid server or port")
            if p.get("type") in ("vless", "vmess"):
                uuid.UUID(str(p.get("uuid", "")))
            if p.get("reality-opts") and not p["reality-opts"].get("public-key"):
                raise ValueError("missing Reality public key")
            base=p["name"]; n=base; k=2
            while n in names:
                n=f"{base[:48]}-{k}"; k+=1
            p["name"]=n; names.add(n); proxies.append(p)
        except Exception:
            errors+=1
    import hashlib
    unique_proxies = []
    signatures = set()
    for p in proxies:
        identity = {k: v for k, v in p.items() if k != "name"}
        signature = hashlib.sha256(json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        if signature not in signatures:
            signatures.add(signature)
            unique_proxies.append(p)
    proxies = unique_proxies
    if not proxies:
        raise SystemExit("No valid unique nodes parsed; refusing to publish an empty profile")

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
            "proxies": proxies,
            "proxy-groups": [{"name": "PROBE", "type": "select", "proxies": [p["name"] for p in proxies]}],
            "rules": ["MATCH,PROBE"]
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
            OUT.mkdir(exist_ok=True)
            startup_report = {
                "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "stage": "mihomo_startup",
                "sources": source_status,
                "uniqueInputLines": len(seen),
                "parsedCandidates": len(proxies),
                "parseErrors": errors,
                "testedNodes": 0, "reachableNodes": 0, "stableNodes": 0,
                "testRounds": 3, "requiredSuccessesPerNode": MIN_SUCCESS_CHECKS,
                "publishedNodes": 0, "maxNodes": MAX_NODES,
                "preferredLatencyMs": int(os.getenv("PREFERRED_LATENCY_MS", "300")),
                "hardLatencyCeilingMs": int(os.getenv("MAX_LATENCY_MS", "600")),
                "failureReason": "Mihomo rejected the candidate configuration during startup.",
                "mihomoLogTail": tail[-1500:],
                "warning": "Public third-party nodes are untrusted; no candidate was published."
            }
            (OUT/"status.json").write_text(json.dumps(startup_report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
            raise SystemExit("Mihomo failed to start; diagnostic report saved and no nodes published. " + tail[-1000:])

        test_urls = [
            os.getenv("TEST_URL_PRIMARY", "https://www.gstatic.com/generate_204"),
            os.getenv("TEST_URL_FALLBACK", "https://cp.cloudflare.com/generate_204")
        ]
        results=[]
        workers=max(4, min(24, int(os.getenv("TEST_WORKERS", "16"))))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures=[pool.submit(test_one, p, test_urls, 3) for p in proxies]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        by_name={r["name"]:r for r in results}
        stable=[p for p in proxies if by_name.get(p["name"],{}).get("stable") is True]
        preferred_limit=int(os.getenv("PREFERRED_LATENCY_MS", "300"))
        max_latency=int(os.getenv("MAX_LATENCY_MS", "600"))
        # Only stable nodes at or below the hard latency ceiling may be published.
        good=[p for p in stable if by_name[p["name"]].get("delay") is not None
              and by_name[p["name"]]["delay"] <= max_latency]
        if not good:
            # Save a diagnostic report even when no node qualifies; the workflow
            # uploads it on failure and leaves the previously published profile untouched.
            OUT.mkdir(exist_ok=True)
            measured = [r["delay"] for r in results if r.get("delay") is not None]
            ranked = sorted((r for r in results if r.get("delay") is not None),
                            key=lambda r: (r["delay"], -r["passedChecks"]))
            failure_report = {
                "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "sources": source_status, "uniqueInputLines": len(seen),
                "parsedCandidates": len(proxies), "parseErrors": errors,
                "testedNodes": len(results),
                "reachableNodes": sum(1 for r in results if r.get("delay") is not None),
                "stableNodes": len(stable), "testRounds": 3,
                "requiredSuccessesPerNode": MIN_SUCCESS_CHECKS,
                "deduplicatedCandidates": len(proxies),
                "speedTest": {"url": os.getenv("SPEED_TEST_URL", "https://speed.cloudflare.com/__down?bytes=524288"),
                              "sampleBytesTarget": 524288, "successful": 0, "failed": 0,
                              "scope": "Not run because no node passed the stability/latency gate"},
                "publishedNodes": 0, "maxNodes": MAX_NODES,
                "maxPublish": int(os.getenv("MAX_PUBLISH", "100")),
                "preferredLatencyMs": preferred_limit, "hardLatencyCeilingMs": max_latency,
                "preferredNodes": 0, "backupNodes": 0,
                "excludedStableOverCeiling": len(stable),
                "testUrls": test_urls,
                "latencyMs": ({"min": min(measured), "median": sorted(measured)[len(measured)//2],
                               "max": max(measured)} if measured else None),
                "topNodes": [{"name": r["name"], "medianDelayMs": r["delay"],
                              "passedChecks": r["passedChecks"],
                              "requiredChecks": r["requiredChecks"]} for r in ranked[:20]],
                "failureReason": f"No candidates met stability and {max_latency}ms latency requirements; prior subscription retained.",
                "warning": "Public third-party nodes are untrusted. GitHub-runner tests do not establish usability or speed on the user's device."
            }
            (OUT/"status.json").write_text(json.dumps(failure_report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
            print(f"No publishable nodes. Diagnostics saved: tested={len(results)}, stable={len(stable)}, ceiling={max_latency}ms.")
            raise SystemExit("No nodes met the publication gate; previous subscription was not changed.")
        # Small serial download probe: one 512 KiB sample per latency-qualified candidate.
        # This ranks GitHub-runner throughput only; it is not a phone/network guarantee.
        speed_results = {}
        speed_url = os.getenv("SPEED_TEST_URL", "https://speed.cloudflare.com/__down?bytes=524288")
        for p in good:
            try:
                speed_results[p["name"]] = download_probe(p["name"], speed_url)
            except Exception as exc:
                speed_results[p["name"]] = {"error": type(exc).__name__, "throughputMbps": None}
        # Latency is the primary ranking criterion; throughput breaks latency ties.
        good.sort(key=lambda p: (
            by_name[p["name"]]["delay"],
            speed_results.get(p["name"], {}).get("throughputMbps") is None,
            -(speed_results.get(p["name"], {}).get("throughputMbps") or 0)
        ))
        # Keep only nodes that completed a real proxied HTTP request; never fall back
        # to publishing syntax-only candidates.
        if not good:
            raise SystemExit("No nodes passed live proxy tests; existing published subscription is left untouched")
        # Detect likely shared backends/credentials without deleting candidates.
        # This is diagnostic only: different server IPs may still be independent exits.
        near_groups = {}
        for p in good:
            identity = {k: v for k, v in p.items()
                        if k not in ("name", "server", "client-fingerprint")}
            sig = hashlib.sha256(json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            near_groups.setdefault(sig, []).append({"name": p["name"], "server": p.get("server")})
        near_duplicate_groups = [items for items in near_groups.values() if len(items) > 1]
        max_publish=int(os.getenv("MAX_PUBLISH", "100"))
        good=good[:max_publish]
        profile={
          "mixed-port":7890,"allow-lan":False,"mode":"rule","log-level":"warning",
          "ipv6":False,
          "proxies":good,
          "proxy-groups":[
            {"name":"AUTO","type":"url-test","proxies":[p["name"] for p in good],
             "url":test_urls[0],"interval":300,"tolerance":100},
            {"name":"PREFERRED_LT_300MS","type":"url-test",
             "proxies":[p["name"] for p in good if by_name[p["name"]]["delay"] < preferred_limit] or [good[0]["name"]],
             "url":test_urls[0],"interval":300,"tolerance":75},
            {"name":"BACKUP_300_600MS","type":"select",
             "proxies":[p["name"] for p in good if preferred_limit <= by_name[p["name"]]["delay"] <= max_latency] or [good[0]["name"]]},
            {"name":"PROXY","type":"select","proxies":["PREFERRED_LT_300MS","AUTO","BACKUP_300_600MS"]+[p["name"] for p in good]},
          ],
          "rules":["MATCH,PROXY"]
        }
        OUT.mkdir(exist_ok=True)
        (OUT/"clash.yaml").write_text(yaml.safe_dump(profile,allow_unicode=True,sort_keys=False),encoding="utf-8")
        delays=[by_name[p["name"]]["delay"] for p in good]
        preferred_count=sum(1 for p in good if by_name[p["name"]]["delay"] < preferred_limit)
        backup_count=len(good)-preferred_count
        report={"generatedAt":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
                "sources":source_status,"uniqueInputLines":len(seen),
                "parsedCandidates":len(proxies),"parseErrors":errors,
                "testedNodes":len(results),"reachableNodes":sum(1 for r in results if r.get("delay") is not None),
                "stableNodes":sum(1 for r in results if r.get("stable") is True),
                "testRounds":3,"requiredSuccessesPerNode":MIN_SUCCESS_CHECKS,"deduplicatedCandidates":len(proxies),
                "speedTest":{"url":speed_url,"sampleBytesTarget":524288,
                             "successful":sum(1 for v in speed_results.values() if v.get("throughputMbps") is not None),
                             "failed":sum(1 for v in speed_results.values() if v.get("throughputMbps") is None),
                             "scope":"GitHub Actions runner only; not representative of the user's device/network"},
                "nearDuplicateGroups":near_duplicate_groups,
                "nearDuplicatePolicy":"diagnostic only; candidates are retained until device-side validation",
                "publishedNodes":len(good),"maxNodes":MAX_NODES,
                "maxPublish":max_publish,"preferredLatencyMs":preferred_limit,
                "hardLatencyCeilingMs":max_latency,"preferredNodes":preferred_count,
                "backupNodes":backup_count,"excludedStableOverCeiling":len(stable)-len(good),
                "testUrls":test_urls,
                "latencyMs":{"min":min(delays),"median":sorted(delays)[len(delays)//2],"max":max(delays)},
                "topNodes":[{"name":p["name"],"medianDelayMs":by_name[p["name"]]["delay"],
                             "throughputMbps":speed_results.get(p["name"],{}).get("throughputMbps"),
                             "speedTestError":speed_results.get(p["name"],{}).get("error"),
                             "passedChecks":by_name[p["name"]]["passedChecks"],
                             "requiredChecks":by_name[p["name"]]["requiredChecks"]} for p in good[:20]],
                "warning":"Public third-party nodes are untrusted. Stability and download throughput are measured from GitHub Actions only; they do not establish privacy or usability/speed from the user's device."}
        (OUT/"status.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        print(f"Live-tested {len(results)} nodes; {len(good)} passed and published.")
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()
        shutil.rmtree(work, ignore_errors=True)

if __name__=="__main__": main()
