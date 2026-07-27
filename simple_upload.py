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
    CONFIG_SERVER_USERNAME=user2
    CONFIG_SERVER_PASSWORD=changeme
    CONFIG_SERVER_PROJECT=myapp
    CONFIG_SERVER_PROFILE=common
    CONFIG_SERVER_LABEL=
"""

import sys
import os
import argparse
import requests
import urllib.parse


def load_env(env_path=".env"):
    """Load variables from a .env file (simple KEY=VALUE parsing)."""
    if not os.path.isfile(env_path):
        print(f"[INFO]: {env_path} not found in current directory. Skipping load env")
        return {}

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
    url = os.getenv("CONFIG_SERVER_URL", env.get("CONFIG_SERVER_URL", ""))
    username = os.getenv("CONFIG_SERVER_USERNAME", env.get("CONFIG_SERVER_USERNAME", ""))
    password = os.getenv("CONFIG_SERVER_PASSWORD", env.get("CONFIG_SERVER_PASSWORD", ""))
    project = os.getenv("CONFIG_SERVER_PROJECT", env.get("CONFIG_SERVER_PROJECT", ""))
    profile = os.getenv("CONFIG_SERVER_PROFILE", env.get("CONFIG_SERVER_PROFILE", "default"))
    label = args.label or os.getenv("CONFIG_SERVER_LABEL", env.get("CONFIG_SERVER_LABEL", ""))

    if not all([url, username, password, project, profile]):
        missing = [k for k in ("CONFIG_SERVER_URL", "CONFIG_SERVER_USERNAME", "CONFIG_SERVER_PASSWORD", "CONFIG_SERVER_PROJECT", "CONFIG_SERVER_PROFILE") if not env.get(k)]
        print(f"Error: missing required .env variables: {', '.join(missing)}")
        sys.exit(1)

    print(f"Config Server: {url}")
    print(f"User: {username}, Project: {project}, Profile: {profile}, Label: '{label}'")
    print(f"Directory: {args.path}")
    print()
    upload_dir(url, username, password, project, profile, args.path, label)

