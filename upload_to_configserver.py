#!/usr/bin/env python3
"""
Upload configuration files from a local path to config-server-go.

If the path is a directory, all files within it are uploaded recursively,
retaining the relative path structure on the remote server.

If the path is a file, only that single file is uploaded.

Usage:
    python3 upload_to_configserver.py <source-path> [directory]

Positional Args:
    source-path       - Path to file or directory to upload (relative to project dir)
    directory         - Project directory (overrides PROJECT_DIR env var)

Environment Variables:
    CONFIGSERVER_BASE_URL   - Config server base URL    (default: http://localhost:7777)
    CONFIG_USER             - Username for auth         (default: user2)
    CONFIG_PASSWORD         - Password for auth         (default: changeme)
    PROJECT_DIR             - Project directory path    (default: current directory)
    APP_NAME                - App name for config       (overrides bruno.json)
    PROFILE                 - Config profile            (default: common)

Examples:
    # Upload the whole test/bruno/environments directory:
    python3 upload_to_configserver.py test/bruno/environments

    # Upload a single file with a custom project directory:
    python3 upload_to_configserver.py test/bruno/environments/DEV.bru .

    # With environment variables:
    CONFIGSERVER_BASE_URL=http://myserver:7777 APP_NAME=MyApp python3 upload_to_configserver.py test/bruno/environments

    # Upload from a different project:
    python3 upload_to_configserver.py environments /path/to/other/project
"""

import os
import sys
import argparse
import base64
import urllib.request
import urllib.error
import urllib.parse
import json


# ---------------------------------------------------------------------------
# Configuration – precedence: CLI arg > env var > hardcoded defaults
# ---------------------------------------------------------------------------

CONFIGSERVER_BASE_URL = os.getenv("CONFIGSERVER_BASE_URL", "http://localhost:7777")
CONFIG_USER = os.getenv("CONFIG_USER", "user2")
CONFIG_PASSWORD = os.getenv("CONFIG_PASSWORD", "changeme")
PROFILE = os.getenv("PROFILE", "common")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_auth_header(user: str, password: str) -> str:
    """Return a Basic Auth header value."""
    credentials = f"{user}:{password}"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    return f"Basic {encoded}"


def build_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> urllib.request.Request:
    """Build a urllib Request."""
    req = urllib.request.Request(url, method=method, data=data)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    return req


def send_request(req: urllib.request.Request) -> tuple[int, str, str | None]:
    """Send the request and return (status_code, response_text, error_or_None)."""
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, body, None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8") if exc.fp else ""
        return exc.code, body, None
    except Exception as exc:
        return 0, "", str(exc)


def get_app_name(project_dir: str) -> str:
    """
    Determine the app name for config-server-go.

    Tries in order:
      1. APP_NAME env var
      2. test/bruno/bruno.json (read "name" field)
      3. Fall back to the directory name of the project root
    """
    # 1. env var takes priority
    app_name = os.getenv("APP_NAME")
    if app_name:
        return app_name

    # 2. bruno.json
    bruno_json_path = os.path.join(project_dir, "test", "bruno", "bruno.json")
    if os.path.isfile(bruno_json_path):
        try:
            with open(bruno_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "name" in data:
                return data["name"]
        except Exception:
            pass

    # 3. fallback – directory name of the project root
    return os.path.basename(os.path.abspath(project_dir))


def get_project_dir(cli_arg: str | None = None) -> str:
    """
    Resolve the project directory.

    Priority: CLI arg > PROJECT_DIR env var > current working directory.
    """
    if cli_arg:
        return os.path.abspath(cli_arg)
    env_dir = os.getenv("PROJECT_DIR")
    if env_dir:
        return os.path.abspath(env_dir)
    return os.getcwd()


def get_remote_path(source_path: str, project_dir: str) -> str:
    """
    Compute the remote path on config-server-go.

    The remote path is the relative path from the project root.
    For a file at project_dir/test/bruno/environments/DEV.bru,
    the remote path is test/bruno/environments/DEV.bru.

    Note: No leading '/' is added — the config-server-go GET endpoint
    constructs the query path as "app/profile/relpath" (no leading slash).
    The upload endpoint stores the path exactly as sent, so the path
    must match the GET query format to be retrievable.
    """
    # source_path is already relative to project_dir
    return source_path.replace("\\", "/")  # ensure forward slashes for URL


def get_file_ext(filename: str) -> str:
    """Extract file extension, e.g. '.yaml' or '.json'."""
    _, ext = os.path.splitext(filename)
    return ext if ext else ""


def upload_file(
    project_dir: str,
    app_name: str,
    source_path: str,
) -> tuple[int, str]:
    """
    Upload a single file to config-server-go.

    Parameters:
        project_dir   - Project root directory
        app_name      - Config server app name
        source_path   - Path relative to project_dir (e.g. "environments/DEV.bru")

    Returns:
        (status_code, response_body)
    """
    full_path = os.path.join(project_dir, source_path)

    if not os.path.isfile(full_path):
        return 404, f"File not found: {full_path}"

    # Read file content
    with open(full_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Determine file extension for upload parameter
    ext = get_file_ext(source_path)
    if not ext:
        return 400, f"No file extension found for: {source_path}"

    # Build the remote path
    remote_path = get_remote_path(source_path, project_dir)

    # Build upload URL
    # POST /upload?app=...&profile=...&ext=...&path=...
    # Properly URL-encode query parameters (app name has dots, path has slashes)
    base_url = CONFIGSERVER_BASE_URL.rstrip("/")
    query_params = urllib.parse.urlencode({
        "app": app_name,
        "profile": PROFILE,
        "ext": ext,
        "path": remote_path,
    })
    url = f"{base_url}/upload?{query_params}"

    # Send request
    headers = {
        "Content-Type": "text/plain",
        "Authorization": build_auth_header(CONFIG_USER, CONFIG_PASSWORD),
    }
    data = content.encode("utf-8")
    req = build_request("POST", url, headers=headers, data=data)

    status_code, body, _ = send_request(req)
    return status_code, body


SUPPORTED_EXTENSIONS = {'.yaml', '.yml', '.json', '.properties', '.conf', '.cfg', '.ini'}

def upload_directory(
    project_dir: str,
    app_name: str,
    source_dir: str,
    skip_unsupported: bool = True,
) -> list[tuple[str, int, str]]:
    """
    Upload all files in a directory recursively to config-server-go.

    Parameters:
        project_dir       - Project root directory
        app_name          - Config server app name
        source_dir        - Directory relative to project_dir (e.g. "environments")
        skip_unsupported  - If True, skip files with unsupported extensions

    Returns:
        List of (source_path, status_code, response_body) for each file uploaded.
    """
    full_dir = os.path.join(project_dir, source_dir)

    if not os.path.isdir(full_dir):
        return [(source_dir, 404, f"Directory not found: {full_dir}")]

    results = []
    skipped = 0

    # Walk the directory recursively
    for dirpath, _dirnames, filenames in os.walk(full_dir):
        for filename in filenames:
            # Build the relative path from project_dir
            rel_dir = os.path.relpath(dirpath, project_dir)
            if rel_dir == ".":
                relative_path = filename
            else:
                relative_path = os.path.join(rel_dir, filename)

            # Ensure forward slashes
            relative_path = relative_path.replace("\\", "/")

            # Check if extension is supported
            ext = get_file_ext(relative_path)
            if skip_unsupported and ext and ext.lower() not in SUPPORTED_EXTENSIONS:
                skipped += 1
                continue

            status_code, body = upload_file(project_dir, app_name, relative_path)
            results.append((relative_path, status_code, body))

    if skipped > 0:
        print(f"  ⚠️  Skipped {skipped} file(s) with unsupported extensions")
        print(f"     Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}")
        print()

    return results


def upload_single_file(
    project_dir: str,
    app_name: str,
    source_path: str,
) -> tuple[int, str]:
    """
    Upload a single file to config-server-go.

    Returns:
        (status_code, response_body)
    """
    full_path = os.path.join(project_dir, source_path)

    if not os.path.isfile(full_path):
        return 404, f"File not found: {full_path}"

    return upload_file(project_dir, app_name, source_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Upload config files from a local path to config-server-go. "
                    "If the path is a directory, all files are uploaded recursively. "
                    "If the path is a file, only that file is uploaded."
    )
    parser.add_argument(
        "source_path",
        help="Path to file or directory to upload (relative to project dir). "
             "Example: test/bruno  or  test/bruno/environments-data.yaml  or  test/bruno/environments",
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=None,
        help="Project directory path (overrides PROJECT_DIR env var).",
    )
    parser.add_argument(
        "--upload-env-data",
        action="store_true",
        help="Also upload environments-data.yaml from test/bruno/ if it exists",
    )
    args = parser.parse_args()

    project_dir = get_project_dir(args.directory)
    app_name = get_app_name(project_dir)

    source_path = args.source_path
    full_source = os.path.join(project_dir, source_path)

    print("=" * 60)
    print("  Config Server Upload")
    print("=" * 60)
    print(f"  Project dir : {project_dir}")
    print(f"  App name    : {app_name}")
    print(f"  Profile     : {PROFILE}")
    print(f"  Config URL  : {CONFIGSERVER_BASE_URL}")
    print(f"  Source path : {source_path}")
    print("=" * 60)
    print()

    all_results = []

    # Special handling for test/bruno/environments-data.yaml
    env_data_path = os.path.join("test", "bruno", "environments-data.yaml")
    env_data_full = os.path.join(project_dir, env_data_path)

    if args.upload_env_data or (source_path == "test/bruno" and os.path.isfile(env_data_full)):
        if os.path.isfile(env_data_full):
            print(f"  => Uploading environments-data.yaml: {env_data_path}")
            print()
            status_code, body = upload_file(project_dir, app_name, env_data_path)
            all_results.append((env_data_path, status_code, body))
            if status_code == 200:
                print(f"  ✅  {env_data_path}  [{status_code}]")
            else:
                print(f"  ❌  {env_data_path}  [{status_code}] {body}")
                if body and status_code != 200:
                    print(f"         {body}")
            print()
        else:
            print(f"  ⚠️  environments-data.yaml not found at: {env_data_full}")
            print()

    if os.path.isdir(full_source):
        # Upload entire directory
        print(f"  => Uploading directory: {source_path}")
        print()
        results = upload_directory(project_dir, app_name, source_path)
        all_results.extend(results)

        success_count = sum(1 for _, s, _ in results if s == 200)
        fail_count = len(results) - success_count
        for rel_path, status, body in results:
            if status == 200:
                print(f"  ✅  {rel_path}  [{status}]")
            else:
                print(f"  ❌  {rel_path}  [{status}] {body}")
                if body and status != 200:
                    print(f"         {body}")

        print()
        print(f"  Directory: Total: {len(results)} files | Success: {success_count} | Failed: {fail_count}")
        print()

    elif os.path.isfile(full_source):
        # Upload single file
        print(f"  => Uploading file: {source_path}")
        print()

        status_code, body = upload_file(project_dir, app_name, source_path)
        all_results.append((source_path, status_code, body))

        if status_code == 200:
            print(f"  ✅  {source_path}  [{status_code}]")
            print(f"         You can fetch the config at: {get_remote_path(source_path, project_dir)}")
        else:
            print(f"  ❌  {source_path}  [{status_code}] {body}")
            if body and status_code != 200:
                print(f"         {body}")
        print()

    else:
        print(f"  ERROR: Path not found: {full_source}")
        sys.exit(1)

    # Summary
    if all_results:
        total = len(all_results)
        success = sum(1 for _, s, _ in all_results if s == 200)
        failed = total - success
        print(f"  Overall: Total: {total} files | Success: {success} | Failed: {failed}")
        print()

    print("=" * 60)


if __name__ == "__main__":
    main()
