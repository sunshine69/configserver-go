import yaml

print("=== Understanding Folded Block Scalar (>) ===\n")

# Test: What happens with multiline decrypted values?
yaml1 = """
connection_string: >
  {cipher}longCipher==
"""
# If ciphertext decrypts to single line with special chars
decoded1 = "postgres://user:p@ssw0rd!#$%^&*()@host/db"
print(f"Single line decoded: {repr(decoded1)}")
parsed = yaml.safe_load(yaml1.replace("{cipher}longCipher==", decoded1))
print(f"Parsed value: {repr(parsed['connection_string'])}")

# If ciphertext decrypts to multiline - THIS IS THE PROBLEM
print("\n--- Problem: Multiline decrypted value ---")
yaml2 = """
config: >
  {cipher}test==
"""
# Simulating what happens if decrypted value has newline
decoded_multiline = "line1\nline2"
result = yaml2.replace("{cipher}test==", decoded_multiline)
print(f"Result after replacement:")
print(result)
print("\nThis BREAKS because 'line2' is not indented properly")

# Test: Using literal block scalar (|) instead
print("\n\n=== Alternative: Literal Block Scalar (|) ===")
yaml_literal = """
password: |
  {cipher}abc123==
"""
decoded = "Secret!@#$%"
result = yaml_literal.replace("{cipher}abc123==", decoded)
print(f"With special chars: {repr(result)}")
parsed = yaml.safe_load(result)
print(f"Parsed: {repr(parsed['password'])}")

# Test: Multiple ciphers in same folded block
print("\n\n=== Multiple ciphers in folded block ===")
yaml_multi = """
config: >
  key1={cipher}cipher1==
  key2={cipher}cipher2==
"""
decoded = "value1"
result = yaml_multi.replace("{cipher}cipher1==", decoded)
print(f"After first decrypt:\n{result}")

# After replacing second
result2 = result.replace("{cipher}cipher2==", "value2")
print(f"\nAfter second decrypt:\n{result2}")
try:
    parsed = yaml.safe_load(result2)
    print(f"Parsed config: {repr(parsed['config'])}")
except Exception as e:
    print(f"Error: {e}")

# Test: Empty cipher value
print("\n\n=== Empty/whitespace handling ===")
yaml_empty = """
value: >
  {cipher}empty==
"""
decoded = ""
result = yaml_empty.replace("{cipher}empty==", decoded)
print(f"Result (empty string):\n{result}")
try:
    parsed = yaml.safe_load(result)
    print(f"Parsed: {repr(parsed['value'])}")
except Exception as e:
    print(f"Error: {e}")

# Test: Cipher value with just whitespace
decoded_ws = "   "
result = yaml_empty.replace("{cipher}empty==", decoded_ws)
print(f"\nResult (whitespace only):\n{result}")
try:
    parsed = yaml.safe_load(result)
    print(f"Parsed: {repr(parsed['value'])}")
except Exception as e:
    print(f"Error: {e}")
