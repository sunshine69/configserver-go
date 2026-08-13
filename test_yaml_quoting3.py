import yaml
import re

def quote_for_yaml(value):
    """
    Returns a properly quoted YAML string representation.
    Handles all special characters that break YAML.
    """
    if not value:  # Empty string
        return '""'
    
    # Check if quoting is needed
    needs_quoting = False
    
    # Characters/sequences that require quoting in YAML
    problematic_chars = set(':{}[]>,|*!?#&-%')
    problematic_patterns = [
        r'^[\s]+',      # Leading whitespace
        r'[\s]+$',      # Trailing whitespace  
        r'^\d+$',       # Pure numbers
        r'^true$|^false$',  # Booleans
        r'^null$|^~$',  # Null values
        r'^\\$',        # Starts with backslash
    ]
    
    for p in problematic_patterns:
        if re.match(p, value):
            needs_quoting = True
            break
    
    if any(c in problematic_chars for c in value):
        needs_quoting = True
    
    if '"' in value or "'" in value:
        needs_quoting = True
    
    if not needs_quoting:
        return value  # No quoting needed
    
    # Choose quote style - prefer single quotes (easier escaping)
    has_single_quote = "'" in value
    
    if has_single_quote:
        # Use double quotes and escape internal double quotes
        escaped = value.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{escaped}"'
    
    # Default: use single quotes (escape single quotes by doubling)
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def process_ciphers_safe(content):
    """
    Generic cipher processor that properly quotes decrypted values.
    Works for ALL special characters: quotes, pipes, colons, hashes, etc.
    """
    pattern = r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}"""
    
    def replace_cipher(match):
        cipher = match.group(0)
        
        # Extract the base64 ciphertext (strip quotes and {cipher} prefix)
        b64 = re.sub(r"^['\"]?{cipher}|['\"]?$", "", cipher)
        
        # SIMULATED DECRYPTION - replace with actual u.Decrypt call
        decrypted = "P@ssw0rd!#$%^&*()=+"  # Keep it simple
        
        # Quote the decrypted value properly
        quoted = quote_for_yaml(decrypted)
        return quoted
    
    return re.sub(pattern, replace_cipher, content)


def process_ciphers_with_quotes(content):
    """
    Simulates decryption with quoted output - handles quotes in value.
    """
    pattern = r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}"""
    
    def replace_cipher(match):
        cipher = match.group(0)
        
        # Check what quote style was used (if any)
        starts_with_single = cipher.startswith("'")
        starts_with_double = cipher.startswith('"')
        
        # Extract the base64 ciphertext (strip quotes and {cipher} prefix)
        b64 = re.sub(r"^['\"]?{cipher}|['\"]?$", "", cipher)
        
        # SIMULATED DECRYPTION - returns value with mixed quotes
        decrypted = 'It\'s a "test" value'  # Value has both types of quotes
        
        # If original was single-quoted, MUST use double quotes for output
        if starts_with_single:
            escaped = decrypted.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'
        
        # Otherwise, try single quotes first (easier to read)
        # But if value has single quote, MUST use double quotes
        if "'" in decrypted:
            escaped = decrypted.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'
        
        escaped = decrypted.replace("'", "''")
        return f"'{escaped}'"
    
    return re.sub(pattern, replace_cipher, content)


# Test cases
print("=== Test 1: Complex special chars ===")
yaml1 = "password: {cipher}abc=="
result1 = process_ciphers_safe(yaml1)
print(f"Input:  {yaml1}")
print(f"Output: {result1}")
parsed1 = yaml.safe_load(result1)
print(f"Parsed: {repr(parsed1['password'])}")

print("\n=== Test 2: Colon in value ===")
yaml2 = "connection: {cipher}test=="
def process_colon(match):
    return quote_for_yaml("postgres://user:p@ss:5432/db")
result2 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", process_colon, yaml2)
print(f"Input:  {yaml2}")
print(f"Output: {result2}")
parsed2 = yaml.safe_load(result2)
print(f"Parsed: {repr(parsed2['connection'])}")

print("\n=== Test 3: Hash/comment character ===")
yaml3 = "note: {cipher}test=="
def process_hash(match):
    return quote_for_yaml("# this is data, not a comment")
result3 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", process_hash, yaml3)
print(f"Input:  {yaml3}")
print(f"Output: {result3}")
parsed3 = yaml.safe_load(result3)
print(f"Parsed: {repr(parsed3['note'])}")

print("\n=== Test 4: Pipe character ===")
yaml4 = "filter: {cipher}test=="
def process_pipe(match):
    return quote_for_yaml("grep foo | awk '{print $1}' | sort")
result4 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", process_pipe, yaml4)
print(f"Input:  {yaml4}")
print(f"Output: {result4}")
parsed4 = yaml.safe_load(result4)
print(f"Parsed: {repr(parsed4['filter'])}")

print("\n=== Test 5: Mixed quotes in value ===")
yaml5 = 'command: "{cipher}test=="'
def process_mixed(match):
    return quote_for_yaml("echo 'hello' and \"world\"")
result5 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", process_mixed, yaml5)
print(f"Input:  {yaml5}")
print(f"Output: {result5}")
parsed5 = yaml.safe_load(result5)
print(f"Parsed: {repr(parsed5['command'])}")

print("\n=== Test 6: Curly braces ===")
yaml6 = "json: {cipher}test=="
def process_braces(match):
    return quote_for_yaml('{"key": "value", "num": 123}')
result6 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", process_braces, yaml6)
print(f"Input:  {yaml6}")
print(f"Output: {result6}")
parsed6 = yaml.safe_load(result6)
print(f"Parsed: {repr(parsed6['json'])}")

print("\n=== Test 7: Square brackets ===")
yaml7 = "list: {cipher}test=="
def process_brackets(match):
    return quote_for_yaml("[1, 2, 3]")
result7 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", process_brackets, yaml7)
print(f"Input:  {yaml7}")
print(f"Output: {result7}")
parsed7 = yaml.safe_load(result7)
print(f"Parsed: {repr(parsed7['list'])}")

print("\n=== Test 8: Empty value ===")
yaml8 = "value: {cipher}test=="
def process_empty(match):
    return quote_for_yaml("")
result8 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", process_empty, yaml8)
print(f"Input:  {yaml8}")
print(f"Output: {result8}")
parsed8 = yaml.safe_load(result8)
print(f"Parsed: {repr(parsed8['value'])}")
