#!/usr/bin/env python3
"""
Simple upload script for config-server-go.

Reads credentials and config from .env file in the current directory.
Only the -path argument is required on the command line.

Usage:
    python3 simple_upload.py -path <dir-path>
    python3 simple_upload.py -path <dir-path> -label dev

.env file contents:
    CONFIG_SERVER_URL=http://localhost:7777
    USERNAME=user2
    PASSWORD=changeme
    PROJECT=myapp
    PROFILE=common
    LABEL=
"""

import sys
import os
import argparse
import requests
import urllib.parse


def load_env(env_path=".env"):
    """Load variables from a .env file (simple KEY=VALUE parsing)."""
    if not os.path.isfile(env_path):
        print(f"Error: {env_path} not found in current directory")
        sys.exit(1)

    env_vars = {}
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                env_vars[key] = value
    return env_vars


def upload_dir(url, username, password, project, profile, dir_path, label=""):
    auth = (username, password)
    dir_path = os.path.normpath(dir_path)
    if not os.path.isdir(dir_path):
        print(f"Error: '{dir_path}' is not a directory")
        sys.exit(1)

    SUPPORTED_EXTS = {".properties", ".yml", ".yaml", ".json"}

    count = 0
    skipped = 0
    for root, dirs, files in os.walk(dir_path):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SUPPORTED_EXTS:
                print(f"  SKIP: {os.path.relpath(os.path.join(root, fname), dir_path)} (unsupported extension: {ext})")
                skipped += 1
                continue

            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, dir_path)
            rel_encoded = urllib.parse.quote(rel, safe="/")

            with open(fpath, "r") as f:
                content = f.read()

            params = {
                "app": project,
                "profile": profile,
                "ext": ext,
                "path": rel_encoded,
            }
            if label:
                params["label"] = label

            upload_url = f"{url}/upload"
            print(f"  Uploading: {rel} -> {upload_url} params={params}")
            resp = requests.post(upload_url, auth=auth, params=params, data=content)
            if resp.status_code == 200:
                result = resp.json()
                print(f"    OK: {result.get('description', 'uploaded')}")
                count += 1
            else:
                print(f"    FAIL: {resp.status_code} {resp.text}")

    print(f"\nDone. Uploaded {count} file(s), skipped {skipped} unsupported extension(s).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Upload config files to config-server-go (creds from .env)"
    )
    parser.add_argument(
        "-path",
        required=True,
        help="Directory path to upload",
    )
    parser.add_argument(
        "-label",
        default="",
        help="Optional label (overrides .env LABEL)",
    )
    args = parser.parse_args()

    env = load_env()

    url = env.get("CONFIG_SERVER_URL", "")
    username = env.get("USERNAME", "")
    password = env.get("PASSWORD", "")
    project = env.get("PROJECT", "")
    profile = env.get("PROFILE", "")
    label = args.label or env.get("LABEL", "")

    if not all([url, username, password, project, profile]):
        missing = [k for k in ("CONFIG_SERVER_URL", "USERNAME", "PASSWORD", "PROJECT", "PROFILE") if not env.get(k)]
        print(f"Error: missing required .env variables: {', '.join(missing)}")
        sys.exit(1)

    print(f"Config Server: {url}")
    print(f"User: {username}, Project: {project}, Profile: {profile}, Label: '{label}'")
    print(f"Directory: {args.path}")
    print()
    upload_dir(url, username, password, project, profile, args.path, label)
