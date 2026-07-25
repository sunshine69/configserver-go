import subprocess, json

base = "http://localhost:7777"
auth = "-u user1:changeme"

# 1. Check profiles format
r = subprocess.run(f"curl -s {base}/myapp/dev.yaml {auth}", shell=True, capture_output=True, text=True)
d = json.loads(r.stdout)
print("profiles:", d.get('profiles'))

# 2. Check app.name key
src = d.get('propertySources', [{}])[0].get('source', {})
print("app.name key exists:", 'app.name' in src)
print("app key exists:", 'app' in src)
print("source keys:", sorted(src.keys())[:10])

# 3. Format-specific endpoints
for url in [f"{base}/myapp-dev.yml", f"{base}/myapp-prod.json", f"{base}/myapp-prod.properties",
            f"{base}/main/myapp-dev.yml", f"{base}/main/myapp-prod.json", f"{base}/main/myapp-prod.properties"]:
    r2 = subprocess.run(f"curl -s -o /dev/null -w '%{{http_code}}' {url} {auth}", shell=True, capture_output=True, text=True)
    print(f"Format endpoint {url.split('/myapp')[1]}: {r2.stdout.strip()}")

# 4. Check multi-profile status code
r3 = subprocess.run(f"curl -s -o /dev/null -w '%{{http_code}}' {base}/myapp/dev,common {auth}", shell=True, capture_output=True, text=True)
print(f"Multi-profile status: {r3.stdout.strip()}")

# 5. Check JSON source keys
r4 = subprocess.run(f"curl -s {base}/myapp/prod.json {auth}", shell=True, capture_output=True, text=True)
d4 = json.loads(r4.stdout)
src4 = d4.get('propertySources', [{}])[0].get('source', {})
print("prod.json source keys:", sorted(src4.keys())[:10])
