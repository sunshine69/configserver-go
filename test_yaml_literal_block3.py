import yaml
import re

print("=== The Core Problem with Block Scalars ===\n")

# When we have multiple ciphers on separate lines:
yaml_before = """config: |-
  host={cipher}host==
  port={cipher}port=="""
print(f"Before decrypt:\n{yaml_before}")
parsed1 = yaml.safe_load(yaml_before)
print(f"Parsed: {repr(parsed1['config'])}\n")

# After decryption, the regex replaces each cipher independently.
# The problem: we need to maintain YAML block scalar indentation.
# Each line inside the block MUST be indented relative to the key.

# CORRECT approach: Replace the ENTIRE block content at once
print("=== Solution: Replace entire block content, not individual ciphers ===\n")

yaml_correct = """config: |-
  host={cipher}host==
  port={cipher}port=="""

# Extract the cipher values first
ciphers1 = re.search(r'\{cipher\}([^=]+)==', yaml_correct)
ciphers2 = re.search(r'\{cipher\}([^=]+)==', yaml_correct.replace(ciphers1.group(0), '', 1))

# Decrypt them
decrypted1 = "localhost"
decrypted2 = "5432"

# Reconstruct the content WITH PROPER INDENTATION
new_content = f"""config: |-
  host={decrypted1}
  port={decrypted2}"""

print(f"Correctly formatted after decrypt:\n{new_content}")
parsed2 = yaml.safe_load(new_content)
print(f"Parsed: {repr(parsed2['config'])}\n")

print("=== Alternative: Single cipher with multiline value ===\n")
# What if the ciphertext itself decrypts to multiple lines?
yaml_multi = """password: |-
  {cipher}multiline=="""

decrypted_multiline = "user1\nuser2\nuser3"

# This MUST maintain indentation for all lines:
correct_multiline = f"""password: |-
  {decrypted_multiline.replace(chr(10), chr(10) + '  ')}"""

print(f"Correctly formatted:\n{correct_multiline}")
parsed3 = yaml.safe_load(correct_multiline)
print(f"Parsed: {repr(parsed3['password'])}\n")

print("=== WRONG (what current code does): ===\n")
wrong_multiline = f"""password: |-
  {decrypted_multiline}"""
print(wrong_multiline)
try:
    parsed4 = yaml.safe_load(wrong_multiline)
    print(f"Parsed (unexpected success): {repr(parsed4['password'])}")
except Exception as e:
    print(f"ERROR (expected): {type(e).__name__}")
    print("  This breaks YAML because lines are not indented!\n")
