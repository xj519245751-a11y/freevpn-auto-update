# freevpn-auto-update

A small GitHub Actions pipeline that periodically collects public third-party proxy URI feeds and builds a bounded Mihomo / Clash Meta YAML profile.

## What it does
- Checks public feeds every four hours (and supports manual runs).
- Accepts VLESS, VMess, Trojan, Shadowsocks and Hysteria2 URI formats.
- Deduplicates exact URI lines, parses supported entries and caps the profile at 250 nodes.
- Publishes `public/clash.yaml` and `public/status.json` on the default branch.
- Uses the Clash client's `url-test` group for client-side latency/reachability selection.

## Important limitations and safety
- Public proxy nodes are operated by unknown third parties. This project does not audit operators, prove privacy, or guarantee reachability.
- Syntax parsing is not a live node health check. The client performs URL testing after import.
- Do not use public nodes for banking, exchange accounts, sensitive work, or private credentials.
- The generated profile is public because this repository is public. Anyone can read the node list.
- GitHub Actions updates the feed; it does not run a VPN service and does not route ChatGPT/cloud traffic through your phone.
- No private subscription URLs, tokens, or personal credentials belong in this repository.

## Output
After the first successful workflow run:
- `https://raw.githubusercontent.com/xj519245751-a11y/freevpn-auto-update/main/public/clash.yaml`
- `https://raw.githubusercontent.com/xj519245751-a11y/freevpn-auto-update/main/public/status.json`

## Run
Open **Actions → Build Clash subscription → Run workflow**. The scheduled job runs every four hours.
