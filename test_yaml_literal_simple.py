import yaml
import re

print("=== Test: |- with quoted output (simpler approach) ===\n")

# Case 1: Value has double quotes inside
yaml1 = """password: |-
  {cipher}test=="""

def decrypt_with_quote1(match):
    decrypted = 'It\'s a "test" value'  # Has both quotes
    # Wrap in single quotes (escape inner single quotes by doubling)
    escaped = decrypted.replace("'", "''")
    return "'" + escaped + "'"

result1 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", decrypt_with_quote1, yaml1)
print(f"After decrypt:\n{result1}")
parsed1 = yaml.safe_load(result1)
print(f"Parsed: {repr(parsed1['password'])}\n")

# Case 2: Value has single quotes inside  
yaml2 = """command: |-
  {cipher}test=="""

def decrypt_with_quote2(match):
    decrypted = 'echo "hello" and \'world\''  # Has both quotes
    # Use double quotes (escape inner double quotes)
    escaped = decrypted.replace('\\', '\\\\').replace('"', '\\"')
    return '"' + escaped + '"'

result2 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", decrypt_with_quote2, yaml2)
print(f"After decrypt:\n{result2}")
parsed2 = yaml.safe_load(result2)
print(f"Parsed: {repr(parsed2['command'])}\n")

# Case 3: Value has neither quote (simple case)
yaml3 = """name: |-
  {cipher}test=="""

def decrypt_simple(match):
    return "SimpleValue123"

result3 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", decrypt_simple, yaml3)
print(f"After decrypt:\n{result3}")
parsed3 = yaml.safe_load(result3)
print(f"Parsed: {repr(parsed3['name'])}\n")

# Case 4: Multiple ciphers in same block (one per line)
yaml4 = """config: |-
  host={cipher}host==
  port={cipher}port=="""

def decrypt_config(match):
    # Return quoted values with proper indentation
    if "host" in match.group(0):
        return "  localhost"  # Keep the indentation!
    elif "port" in match.group(0):
        return "  5432"       # Keep the indentation!
    return match.group(0)

result4 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", decrypt_config, yaml4)
print(f"After decrypt:\n{result4}")
parsed4 = yaml.safe_load(result4)
print(f"Parsed: {repr(parsed4['config'])}\n")

# Case 5: Cipher with special chars (colon, hash, pipe)
yaml5 = """connection: |-
  {cipher}test=="""

def decrypt_special(match):
    return "  postgres://user:p@ss#word|grep"  # Has special chars but indented

result5 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", decrypt_special, yaml5)
print(f"After decrypt:\n{result5}")
parsed5 = yaml.safe_load(result5)
print(f"Parsed: {repr(parsed5['connection'])}\n")

print("=== Summary ===")
print("With |- (literal block scalar), we just need to:")
print("1. Keep the value on one line (no newlines in password)")
print("2. Maintain the 2-space indentation from the parent key")
print("3. Optionally quote if it contains special YAML chars")
