import yaml
import re

print("=== Test 1: Basic |- usage with cipher ===")
yaml1 = """password: |-
  {cipher}AbCdEfGh=="""
print(f"YAML:\n{yaml1}")
parsed1 = yaml.safe_load(yaml1)
print(f"Parsed (before decrypt): {repr(parsed1['password'])}")

# Simulate decryption
decrypted1 = parsed1['password'].replace('{cipher}AbCdEfGh==', 'Secret!@#$')
print(f"After decrypt: {repr(decrypted1)}")

print("\n=== Test 2: Cipher with special chars in |- ===")
yaml2 = """password: |-
  {cipher}test=="""
parsed2 = yaml.safe_load(yaml2)
# Simulate decryption - value has colons and hash
decrypted2 = parsed2['password'].replace('{cipher}test==', 'postgres://user:p@ss#word')
print(f"After decrypt: {repr(decrypted2)}")

# Now test if this YAML would be valid if we served it directly
yaml_served = f"password: |-\n  {decrypted2}"
print(f"Served YAML:\n{yaml_served}")
try:
    parsed3 = yaml.safe_load(yaml_served)
    print(f"Parsed: {repr(parsed3['password'])}")
except Exception as e:
    print(f"ERROR: {e}")

print("\n=== Test 3: Multiline decrypted value in |- ===")
yaml3 = """data: |-
  {cipher}test=="""
parsed4 = yaml.safe_load(yaml3)
# Simulate multiline password (has newline)
decrypted3 = parsed4['password'].replace('{cipher}test==', 'line1\nline2')
print(f"Decrypted value: {repr(decrypted3)}")

yaml_served3 = f"data: |-\n  {decrypted3}"
print(f"Served YAML:\n{yaml_served3}")
try:
    parsed5 = yaml.safe_load(yaml_served3)
    print(f"Parsed: {repr(parsed5['data'])}")
except Exception as e:
    print(f"ERROR - THIS IS THE PROBLEM:")
    print(f"  Multiline values break |- because 'line2' is not indented!")

print("\n=== Test 4: Multiple ciphers in same |- block ===")
yaml4 = """config: |-
  host={cipher}host==
  port={cipher}port=="""
parsed6 = yaml.safe_load(yaml4)
print(f"Parsed (before decrypt): {repr(parsed6['config'])}")

# Decrypt each cipher
decrypted_config = parsed6['config']
decrypted_config = decrypted_config.replace('{cipher}host==', 'localhost')
decrypted_config = decrypted_config.replace('{cipher}port==', '5432')
print(f"After decrypt: {repr(decrypted_config)}")

yaml_served4 = f"config: |-\n  {decrypted_config}"
print(f"Served YAML:\n{yaml_served4}")
try:
    parsed7 = yaml.safe_load(yaml_served4)
    print(f"Parsed: {repr(parsed7['config'])}")
    print("SUCCESS!")
except Exception as e:
    print(f"ERROR: {e}")

print("\n=== Test 5: What about empty value? ===")
yaml5 = """value: |-
  {cipher}empty=="""
parsed8 = yaml.safe_load(yaml5)
decrypted5 = parsed8['value'].replace('{cipher}empty==', '')
print(f"Decrypted (empty): {repr(decrypted5)}")

yaml_served5 = f"value: |-\n  {decrypted5}"
print(f"Served YAML:\n{yaml_served5}")
try:
    parsed9 = yaml.safe_load(yaml_served5)
    print(f"Parsed: {repr(parsed9['value'])}")
except Exception as e:
    print(f"ERROR: {e}")
