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


def request_oidc_token() -> str:
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    separator = "&" if "?" in url else "?"
    audience = urllib.parse.quote(os.environ["ENQRYPTA_OIDC_AUDIENCE"], safe="")
    request = urllib.request.Request(
        f"{url}{separator}audience={audience}",
        headers={"Authorization": f"Bearer {os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)["value"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input")
    parser.add_argument("--bind-execution", action="store_true")
    args = parser.parse_args()
    code_scan_id = os.environ.get("ENQRYPTA_CODE_SCAN_ID", "").strip()
    if args.bind_execution:
        if not code_scan_id:
            return
        if not code_scan_id.startswith("code-launch-") or any(
            char not in "0123456789abcdef-" for char in code_scan_id.removeprefix("code-launch-")
        ):
            parser.error("invalid code scan launch identifier")
        data = {}
        endpoint = f"scans/launches/{code_scan_id}/execution"
    else:
        if not args.input:
            parser.error("--input is required when publishing findings")
        data = json.loads(Path(args.input).read_text())
        notify = os.environ.get("ENQRYPTA_NOTIFY_ON_COMPLETE", "").lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if notify:
            data["notify_on_complete"] = True
            data["notification_email"] = os.environ.get("ENQRYPTA_NOTIFICATION_EMAIL", "")
        nightly_job_task_id = os.environ.get("ENQRYPTA_NIGHTLY_JOB_TASK_ID", "").strip()
        if nightly_job_task_id:
            data["nightly_job_task_id"] = nightly_job_task_id
        if code_scan_id:
            data["code_scan_id"] = code_scan_id
        endpoint = "scans/opengrep"
    payload = json.dumps(data, separators=(",", ":")).encode()
    token = request_oidc_token()
    url = f"{os.environ['ENQRYPTA_API_URL'].rstrip('/')}/api/v1/agent/asset/repos/{endpoint}"
    request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": (
                "Mozilla/5.0 (compatible; EnQrypta-GitHub-Action/5.0; "
                "+https://github.com/dhyey-qvh/enqrypta-actions)"
            ),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            print(response.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        request_id = exc.headers.get("x-request-id") or exc.headers.get("cf-ray")
        print(f"EnQrypta API request failed: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        print(f"Response: {body or '<empty>'}", file=sys.stderr)
        print(f"Request ID: {request_id or '<none>'}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
