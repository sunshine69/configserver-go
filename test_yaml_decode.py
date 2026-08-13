import yaml

# Test 1: Basic folded scalar with cipher (simulating decryption)
yaml1 = """
password: >
  {cipher}ABC123==
name: test-app
"""

# After decryption (what the server would serve)
decoded1 = yaml1.replace("{cipher}ABC123==", "SuperSecret!@#$%^&*()")

print("=== Test 1: Special chars in folded block ===")
print(yaml1)
print("\nAfter decrypt:")
print(decoded1)

# Parse both
parsed1 = yaml.safe_load(yaml1)
parsed2 = yaml.safe_load(decoded1)
print(f"\nParsed cipher value: {repr(parsed1['password'])}")
print(f"Parsed decoded value: {repr(parsed2['password'])}")

# Test 2: What if decrypted text has newlines?
yaml2 = """
connection_string: >
  {cipher}longCipher==
"""
decoded2 = yaml2.replace("{cipher}longCipher==", "postgres://user:p@ss\nword@host/db")
print("\n=== Test 2: Decrypted text with embedded newline ===")
print("After decrypt:")
print(decoded2)
parsed3 = yaml.safe_load(decoded2)
print(f"Value: {repr(parsed3['connection_string'])}")

# Test 3: Multiple ciphers in folded block
yaml3 = """
database: >
  host={cipher}hostCipher==
  port={cipher}portCipher==
"""
decoded3 = yaml3.replace("{cipher}hostCipher==", "localhost").replace("{cipher}portCipher==", "5432")
print("\n=== Test 3: Multiple ciphers in folded block ===")
print(decoded3)
parsed4 = yaml.safe_load(decoded3)
print(f"Value: {repr(parsed4['database'])}")

# Edge case: What about empty lines in folded scalar?
yaml_empty = """
multiline: >

  {cipher}test==
"""
print("\n=== Test: Empty line after > ===")
try:
    parsed = yaml.safe_load(yaml_empty)
    print(f"Parsed: {repr(parsed['multiline'])}")
except Exception as e:
    print(f"Error: {e}")

# Edge case: What if cipher is the only thing in block?
yaml_single = """
password: >
  {cipher}abc123==
"""
print("\n=== Test: Single line folded ===")
parsed = yaml.safe_load(yaml_single)
print(f"Value: {repr(parsed['password'])}")

# Edge case: Decoded value with leading newline
yaml_leading_newline = """
data: >
  {cipher}test==
"""
decoded = yaml_leading_newline.replace("{cipher}test==", "\nsecret")
print("\n=== Test: Decoded value starts with newline ===")
print(decoded)
try:
    parsed = yaml.safe_load(decoded)
    print(f"Value: {repr(parsed['data'])}")
except Exception as e:
    print(f"Error: {e}")

# Edge case: Special chars that look like YAML syntax
yaml_special = """
password: >
  {cipher}abc123==
"""
decoded = yaml_special.replace("{cipher}abc123==", "{nested: value}")
print("\n=== Test: Decoded value looks like YAML ===")
print(decoded)
try:
    parsed = yaml.safe_load(decoded)
    print(f"Value: {repr(parsed['password'])}")
except Exception as e:
    print(f"Error: {e}")

# Edge case: # comment-like content
yaml_comment = """
note: >
  {cipher}abc123==
"""
decoded = yaml_comment.replace("{cipher}abc123==", "# this is not a comment")
print("\n=== Test: Decoded value with # ===")
print(decoded)
try:
    parsed = yaml.safe_load(decoded)
    print(f"Value: {repr(parsed['note'])}")
except Exception as e:
    print(f"Error: {e}")
