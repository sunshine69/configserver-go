#!/usr/bin/env python3
"""
Simple upload script for config-server-go.

Usage:
    python3 simple_upload.py <config-server-url> <username> <password> <project> <profile> <dir-path> [label]

Example:
    python3 simple_upload.py http://localhost:7777 user2 changeme myapp common ./config-data
    python3 simple_upload.py http://localhost:7777 user2 changeme myapp common ./config-data dev
"""

import sys
import os
import requests
import urllib.parse


def upload_dir(url, username, password, project, profile, dir_path, label=""):
    auth = (username, password)
    # Normalize path
    dir_path = os.path.normpath(dir_path)
    if not os.path.isdir(dir_path):
        print(f"Error: '{dir_path}' is not a directory")
        sys.exit(1)

    count = 0
    for root, dirs, files in os.walk(dir_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            # Compute relative path from dir_path
            rel = os.path.relpath(fpath, dir_path)
            # URL-encode the relative path
            rel_encoded = urllib.parse.quote(rel, safe="/")

            # Read file content
            with open(fpath, "r") as f:
                content = f.read()

            # Build upload URL with path param
            params = {
                "app": project,
                "profile": profile,
                "ext": os.path.splitext(fname)[1] or ".yaml",
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

    print(f"\nDone. Uploaded {count} file(s).")


if __name__ == "__main__":
    if len(sys.argv) < 7:
        print(__doc__)
        sys.exit(1)

    url = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    project = sys.argv[4]
    profile = sys.argv[5]
    dir_path = sys.argv[6]
    label = sys.argv[7] if len(sys.argv) > 7 else ""

    print(f"Config Server: {url}")
    print(f"User: {username}, Project: {project}, Profile: {profile}, Label: '{label}'")
    print(f"Directory: {dir_path}")
    print()
    upload_dir(url, username, password, project, profile, dir_path, label)
