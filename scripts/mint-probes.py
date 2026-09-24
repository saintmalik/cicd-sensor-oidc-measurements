#!/usr/bin/env python3
"""OIDC mint probes: request-token lifetime, remint after sleep, request-URL host."""
from __future__ import annotations

import base64, json, os, sys, time, urllib.parse, urllib.request
from datetime import datetime, timezone


def jwt_times(raw: str):
    pad = "=" * (-len(raw.split(".")[1]) % 4)
    c = json.loads(base64.urlsafe_b64decode(raw.split(".")[1] + pad))
    iat, exp = c.get("iat"), c.get("exp")
    return {"iat": iat, "exp": exp, "lifetime_seconds": (exp or 0) - (iat or 0),
            "iss": c.get("iss"), "aud": c.get("aud")}


def mint(url: str, tok: str, aud: str, label: str):
    p = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(p.query)
    q["audience"] = [aud]
    u = urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode({k: v[0] for k, v in q.items()})))
    req = urllib.request.Request(u, method="GET",
        headers={"Authorization": f"bearer {tok}", "Accept": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.load(resp)
        raw = body.get("value") or body.get("token") or ""
        return {"ok": True, "label": label, "http_status": getattr(resp, "status", 200),
                "elapsed_ms": int((time.time() - t0) * 1000),
                "id_token_times": jwt_times(raw) if raw else None}


def main() -> int:
    url, tok = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"], os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    aud = os.environ.get("MANAGER_AUDIENCE", "https://cicd-sensor-manager.example.com")
    sleep_s = int(os.environ.get("SLEEP_SECONDS", "300"))
    out_path = os.environ.get("OUT_PATH", "/tmp/oidc-mint-probes/results.json")
    host = urllib.parse.urlparse(url).hostname or ""
    out = {
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "runner": os.environ.get("RUNNER_NAME", ""),
        "github_repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "request_url_host": host,
        "request_token_lifetime": jwt_times(tok) if tok.count(".") >= 2 else None,
        "sleep_seconds": sleep_s,
        "mint_baseline": mint(url, tok, aud, "baseline"),
    }
    if sleep_s > 0:
        time.sleep(sleep_s)
        out["mint_after_sleep"] = mint(url, tok, aud, f"after_sleep_{sleep_s}s")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    open(out_path, "w").write(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=2))
    ok = bool(host) and out["request_token_lifetime"] and out["mint_baseline"]["ok"]
    if sleep_s > 0:
        ok = ok and out.get("mint_after_sleep", {}).get("ok")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
