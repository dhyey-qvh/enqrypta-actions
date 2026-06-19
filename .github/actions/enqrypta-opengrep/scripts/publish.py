#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _error_body(exc: urllib.error.HTTPError) -> str:
    return exc.read().decode(errors="replace").strip()


def request_oidc_token() -> str:
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    separator = "&" if "?" in url else "?"
    audience = urllib.parse.quote(os.environ["ENQRYPTA_OIDC_AUDIENCE"], safe="")
    request = urllib.request.Request(
        f"{url}{separator}audience={audience}",
        headers={"Authorization": f"Bearer {os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)["value"]
    except urllib.error.HTTPError as exc:
        print(f"GitHub OIDC token request failed: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        body = _error_body(exc)
        if body:
            print(body, file=sys.stderr)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    data = json.loads(Path(args.input).read_text())
    notify = os.environ.get("ENQRYPTA_NOTIFY_ON_COMPLETE", "").lower() in {"1", "true", "yes", "on"}
    if notify:
        data["notify_on_complete"] = True
        data["notification_email"] = os.environ.get("ENQRYPTA_NOTIFICATION_EMAIL", "")

    payload = json.dumps(data, separators=(",", ":")).encode()
    token = request_oidc_token()
    url = f"{os.environ['ENQRYPTA_API_URL'].rstrip('/')}/api/v1/agent/asset/repos/scans/opengrep"
    request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            print(response.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"EnQrypta API publish failed: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        print(f"URL: {url}", file=sys.stderr)
        print(f"Findings: {len(data.get('findings', []))}", file=sys.stderr)
        body = _error_body(exc)
        if body:
            print(body, file=sys.stderr)
        raise


if __name__ == "__main__":
    main()