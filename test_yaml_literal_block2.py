import yaml
import re

print("=== Understanding |- (literal block scalar) ===\n")

# Test 1: Single line cipher in |-
yaml1 = """password: |-
  {cipher}AbCdEfGh=="""
print(f"Before decrypt:\n{yaml1}")
parsed1 = yaml.safe_load(yaml1)
print(f"Parsed: {repr(parsed1['password'])}\n")

# Simulate decryption - what the server would produce
decrypted1 = "Secret!@#$%^&*()"
result1 = f"password: |-\n  {decrypted1}"
print(f"After decrypt:\n{result1}")
parsed2 = yaml.safe_load(result1)
print(f"Parsed: {repr(parsed2['password'])}\n")

# Test 2: Cipher with special chars that would break inline YAML
yaml2 = """connection: |-
  {cipher}test=="""
decrypted2 = "postgres://user:p@ss#word:5432/db"
result2 = f"connection: |-\n  {decrypted2}"
print(f"After decrypt (with special chars):\n{result2}")
parsed3 = yaml.safe_load(result2)
print(f"Parsed: {repr(parsed3['connection'])}\n")

# Test 3: Cipher with quotes
yaml3 = """command: |-
  {cipher}test=="""
decrypted3 = 'echo "hello" and \'world\''
result3 = f"command: |-\n  {decrypted3}"
print(f"After decrypt (with mixed quotes):\n{result3}")
parsed4 = yaml.safe_load(result3)
print(f"Parsed: {repr(parsed4['command'])}\n")

# Test 4: Multiple ciphers on separate lines in same block
yaml4 = """config: |-
  host={cipher}host==
  port={cipher}port=="""
print(f"Before decrypt:\n{yaml4}")
parsed5 = yaml.safe_load(yaml4)
print(f"Parsed before: {repr(parsed5['config'])}\n")

# Decrypt both
decrypted4 = parsed5['config']
decrypted4 = decrypted4.replace('{cipher}host==', 'localhost')
decrypted4 = decrypted4.replace('{cipher}port==', '5432')
result4 = f"config: |-\n  {decrypted4}"
print(f"After decrypt:\n{result4}")
parsed6 = yaml.safe_load(result4)
print(f"Parsed after: {repr(parsed6['config'])}\n")

# Test 5: What about empty value?
yaml5 = """value: |-
  {cipher}empty=="""
decrypted5 = ""
result5 = f"value: |-\n  {decrypted5}"
print(f"After decrypt (empty):\n{result5}")
try:
    parsed7 = yaml.safe_load(result5)
    print(f"Parsed: {repr(parsed7['value'])}\n")
except Exception as e:
    print(f"ERROR: {e}\n")

# Test 6: What if decrypted value has trailing newline?
yaml6 = """data: |-
  {cipher}test=="""
decrypted6 = "value\n"
result6 = f"data: |-\n  {decrypted6}"
print(f"After decrypt (with trailing newline):\n{result6}")
try:
    parsed8 = yaml.safe_load(result6)
    print(f"Parsed: {repr(parsed8['data'])}\n")
except Exception as e:
    print(f"ERROR: {e}\n")

# Test 7: The problematic case - multiline decrypted value
yaml7 = """password: |-
  {cipher}test=="""
decrypted7 = "line1\nline2"
result7 = f"password: |-\n  {decrypted7}"
print(f"After decrypt (MULTILINE - PROBLEMATIC):\n{result7}")
try:
    parsed9 = yaml.safe_load(result7)
    print(f"Parsed: {repr(parsed9['password'])}\n")
except Exception as e:
    print(f"ERROR: {e}\n")
