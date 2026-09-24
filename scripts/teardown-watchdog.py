#!/usr/bin/env python3
"""Background OIDC mint watchdog for GitHub-hosted VM teardown (measurement #4).

Copies Actions OIDC request credentials at start, traps SIGTERM/SIGINT, attempts a
GET mint (same shape as Actions toolkit / cosign), and POSTs a redacted JSON result
to an external sink that survives job artifact teardown.
"""
from __future__ import annotations

import base64
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def jwt_times(raw: str):
    if not raw or raw.count(".") < 2:
        return None
    pad = "=" * (-len(raw.split(".")[1]) % 4)
    c = json.loads(base64.urlsafe_b64decode(raw.split(".")[1] + pad))
    iat, exp = c.get("iat"), c.get("exp")
    return {
        "iat": iat,
        "exp": exp,
        "lifetime_seconds": (exp or 0) - (iat or 0),
        "iss": c.get("iss"),
        "aud": c.get("aud"),
    }


def post_sink(sink_url: str, payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        sink_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()


def mint(url: str, tok: str, aud: str) -> dict:
    p = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(p.query)
    q["audience"] = [aud]
    u = urllib.parse.urlunparse(
        p._replace(query=urllib.parse.urlencode({k: v[0] for k, v in q.items()}))
    )
    req = urllib.request.Request(
        u,
        method="GET",
        headers={"Authorization": f"bearer {tok}", "Accept": "application/json"},
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.load(resp)
            raw = body.get("value") or body.get("token") or ""
            return {
                "ok": True,
                "http_status": getattr(resp, "status", 200),
                "elapsed_ms": int((time.time() - t0) * 1000),
                "id_token_times": jwt_times(raw) if raw else None,
                "got_token": bool(raw),
            }
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            pass
        return {
            "ok": False,
            "http_status": e.code,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "error": f"HTTPError:{e.code}",
            "error_body_prefix": err_body,
        }
    except Exception as e:
        return {
            "ok": False,
            "http_status": None,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "error": f"{type(e).__name__}:{e}",
        }


def main() -> int:
    sink = os.environ["TEARDOWN_SINK_URL"]
    # Copy credentials immediately — do not re-read after signal.
    req_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    req_tok = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    aud = os.environ.get("MANAGER_AUDIENCE", "https://cicd-sensor-manager.example.com")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    job = os.environ.get("GITHUB_JOB", "")
    started_at = utc_now()

    post_sink(
        sink,
        {
            "kind": "watchdog_started",
            "window": "gh_hosted_vm_teardown_sigterm",
            "started_at": started_at,
            "github_run_id": run_id,
            "github_job": job,
            "pid": os.getpid(),
        },
    )

    handled = {"done": False}

    def on_signal(signum, _frame):
        if handled["done"]:
            return
        handled["done"] = True
        sig_name = signal.Signals(signum).name
        received_at = utc_now()
        mint_result = mint(req_url, req_tok, aud)
        payload = {
            "kind": "teardown_mint",
            "window": "gh_hosted_vm_teardown_sigterm",
            "ok": bool(mint_result.get("ok")),
            "http_status": mint_result.get("http_status"),
            "signal": sig_name,
            "started_at": started_at,
            "signal_received_at": received_at,
            "reported_at": utc_now(),
            "github_run_id": run_id,
            "github_job": job,
            "pid": os.getpid(),
            "mint": mint_result,
        }
        try:
            post_sink(sink, payload)
        except Exception as e:
            # Best-effort stderr; sink may already be unreachable.
            sys.stderr.write(f"sink_post_failed:{type(e).__name__}:{e}\n")
        # Exit cleanly after report so runner cleanup can finish.
        os._exit(0 if payload["ok"] else 2)

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    # Stay alive until the runner tears down the VM / process group.
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        sys.stderr.write(f"watchdog_fatal:{type(e).__name__}:{e}\n")
        sys.exit(1)
