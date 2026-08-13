import yaml
import re

def decrypt_and_quote(content):
    """
    Simulates decryption with proper YAML quoting.
    In real code, this would call the actual u.Decrypt function.
    """
    def process_match(match):
        cipher = match.group(0)
        # Extract just the base64 part (strip {cipher} and quotes)
        b64 = re.sub(r"^['\"]?{cipher}|['\"]?$", "", cipher)
        
        # Simulated decryption
        decrypted = "P@ssw0rd!#\$%^&*()=+"  # Special chars
        
        # Now we need to figure out proper YAML quoting
        # Check what quote style was used (if any)
        if cipher.startswith("'") and cipher.endswith("'"):
            # Was single-quoted - use double quotes for output
            return f'"{decrypted}"'
        elif cipher.startswith('"') and cipher.endswith('"'):
            # Was double-quoted - use single quotes for output
            return f"'{decrypted}'"
        else:
            # No quotes originally - need to figure out safest quoting
            # If it contains special chars, we MUST quote
            if any(c in decrypted for c in ':#{}[]-,?|*!><'):
                # Use double quotes and escape internal double quotes
                escaped = decrypted.replace('\\', '\\\\').replace('"', '\\"')
                return f'"{escaped}"'
            return decrypted
    
    pattern = r"""['"]?\{cipher\}[^}'"]+['"]?"""
    return re.sub(pattern, process_match, content)


# Test cases
print("=== Test 1: Password with special chars (no quotes originally) ===")
yaml1 = "password: {cipher}abc123=="
result1 = decrypt_and_quote(yaml1)
print(f"Input:  {yaml1}")
print(f"Output: {result1}")
parsed1 = yaml.safe_load(result1)
print(f"Parsed: {repr(parsed1['password'])}")

print("\n=== Test 2: Password with colon (would break YAML) ===")
yaml2 = "connection: {cipher}test=="
# Simulate password with colon
def process_with_colon(match):
    return '"host:port/db"'
result2 = re.sub(r"""['"]?\{cipher\}[^}'"]+['"]?""", process_with_colon, yaml2)
print(f"Input:  {yaml2}")
print(f"Output: {result2}")
parsed2 = yaml.safe_load(result2)
print(f"Parsed: {repr(parsed2['connection'])}")

print("\n=== Test 3: Password with hash (would be comment) ===")
yaml3 = "note: {cipher}test=="
def process_with_hash(match):
    return '"# not a comment"'
result3 = re.sub(r"""['"]?\{cipher\}[^}'"]+['"]?""", process_with_hash, yaml3)
print(f"Input:  {yaml3}")
print(f"Output: {result3}")
parsed3 = yaml.safe_load(result3)
print(f"Parsed: {repr(parsed3['note'])}")

print("\n=== Test 4: Password with single quote (original single-quoted) ===")
yaml4 = "password: '{cipher}abc=='"
def process_single_quote(match):
    return '"It\'s a secret!"'  # Can't use single quotes inside single quotes
result4 = re.sub(r"""['"]?\{cipher\}[^}'"]+['"]?""", process_single_quote, yaml4)
print(f"Input:  {yaml4}")
print(f"Output: {result4}")
parsed4 = yaml.safe_load(result4)
print(f"Parsed: {repr(parsed4['password'])}")

print("\n=== Test 5: Password with double quote (original double-quoted) ===")
yaml5 = 'password: "{cipher}abc=="'
def process_double_quote(match):
    return "'He said \"hello\"'"
result5 = re.sub(r"""['"]?\{cipher\}[^}'"]+['"]?""", process_double_quote, yaml5)
print(f"Input:  {yaml5}")
print(f"Output: {result5}")
parsed5 = yaml.safe_load(result5)
print(f"Parsed: {repr(parsed5['password'])}")

print("\n=== Test 6: Password with pipe character ===")
yaml6 = "filter: {cipher}abc=="
def process_pipe(match):
    return '"grep | awk | sed"'
result6 = re.sub(r"""['"]?\{cipher\}[^}'"]+['"]?""", process_pipe, yaml6)
print(f"Input:  {yaml6}")
print(f"Output: {result6}")
parsed6 = yaml.safe_load(result6)
print(f"Parsed: {repr(parsed6['filter'])}")

print("\n=== Test 7: Password with curly braces ===")
yaml7 = "json: {cipher}abc=="
def process_braces(match):
    return '"{key: value}"'
result7 = re.sub(r"""['"]?\{cipher\}[^}'"]+['"]?""", process_braces, yaml7)
print(f"Input:  {yaml7}")
print(f"Output: {result7}")
parsed7 = yaml.safe_load(result7)
print(f"Parsed: {repr(parsed7['json'])}")

print("\n=== Test 8: Password with square brackets ===")
yaml8 = "list: {cipher}abc=="
def process_brackets(match):
    return '"[a, b, c]"'
result8 = re.sub(r"""['"]?\{cipher\}[^}'"]+['"]?""", process_brackets, yaml8)
print(f"Input:  {yaml8}")
print(f"Output: {result8}")
parsed8 = yaml.safe_load(result8)
print(f"Parsed: {repr(parsed8['list'])}")
