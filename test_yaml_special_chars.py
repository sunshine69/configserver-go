import yaml
import base64

print("=== Testing YAML Quoting for Special Chars ===\n")

# Problem cases
test_cases = [
    'p@ss"w0rd',           # double quote
    "p's'w'o'r'd",        # single quote  
    'line1|newline2',      # pipe char
    ': key: value',        # colon-space (looks like mapping)
    '# comment text',      # hash
    '> folded',            # greater-than
    '- dash',              # dash
    '? question',          # question mark
]

for pwd in test_cases:
    print(f"\nOriginal: {repr(pwd)}")
    
    # Double quoted - breaks with "
    dq = yaml.safe_dump({'password': f'"{pwd}"'}, default_style='"')
    try:
        parsed = yaml.safe_load(dq)
        result = parsed['password']
        print(f"  Double-quoted: {repr(result)} {'✓' if result == pwd else '✗'}")
    except Exception as e:
        print(f"  Double-quoted: ERROR - {e}")
    
    # Single quoted - breaks with '
    sq = yaml.safe_dump({'password': f"'{pwd}'"}, default_style="'")
    try:
        parsed = yaml.safe_load(sq)
        result = parsed['password']
        print(f"  Single-quoted: {repr(result)} {'✓' if result == pwd else '✗'}")
    except Exception as e:
        print(f"  Single-quoted: ERROR - {e}")

# Test unquoted with special chars
print("\n\n=== Unquoted Values ===")
yaml_unquoted = """
password: : key: value # comment
note: > folded
item: - dash
"""
try:
    parsed = yaml.safe_load(yaml_unquoted)
    print(f"Parsed: {parsed}")
except Exception as e:
    print(f"ERROR: {e}")

# The REAL solution: Base64 encode the ciphertext
print("\n\n=== Solution: Base64 Encode Cipher Text ===")
base64_tests = [
    'p@ss"w0rd',
    "p's'w'o'r'd",
    'line1|newline2',
    ': key: value # comment > - ? ',
    'a]b[c{d}e:f=g',  # brackets, braces, colons
]

for pwd in base64_tests:
    b64 = base64.b64encode(pwd.encode()).decode()
    yaml_str = f"password: {{cipher}}{b64}"
    print(f"\nOriginal: {repr(pwd)}")
    print(f"Cipher format: {yaml_str}")
    
    # Simulate decryption
    decoded = base64.b64decode(b64).decode()
    print(f"Decoded:  {repr(decoded)} {'✓' if decoded == pwd else '✗'}")

# Test YAML parsing with base64 ciphers
print("\n\n=== Full YAML Parsing Test ===")
yaml_with_b64 = """
database:
  password: "{cipher}cGFzc3dvcmQ="
  host: localhost
  connection: "postgres://user:p@ssw0rd!#$%^&*()@host/db"
"""
print(yaml_with_b64)

# After decryption simulation
decoded_yaml = yaml_with_b64.replace("{cipher}cGFzc3dvcmQ=", "super_secret")
parsed = yaml.safe_load(decoded_yaml)
print(f"\nParsed password: {repr(parsed['database']['password'])}")
