import yaml
import re

def quote_for_yaml(value):
    """Quote a value for YAML output"""
    if '"' in value and "'" not in value:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    elif "'" in value and '"' not in value:
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    elif '"' in value and "'" in value:
        # Both quotes - use double quotes and escape the double quotes
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    else:
        # No quotes - check if quoting is needed for other reasons
        problematic = set(':{}[]>,|*!?#&-%')
        if any(c in problematic for c in value):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        return value


def process_ciphers_in_block(content, user_key):
    """
    Process cipher values inside a YAML block scalar (| or |-).
    Maintains proper indentation.
    """
    lines = content.split('\n')
    result = []
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Check if this is a block scalar declaration
        block_match = re.match(r'^(\s*\w+\s*:\s*)(\|[-~]?)\s*$', line)
        
        if block_match:
            indent_prefix = block_match.group(1)  # "key: " with proper indentation
            block_type = block_match.group(2)     # "|", "|-", or "|~"
            
            result.append(line)  # Add the header line
            
            i += 1
            # Process all indented lines until we hit a non-indented line
            while i < len(lines):
                next_line = lines[i]
                
                # Check if this line is still part of the block (indented)
                if next_line.strip() == '' or next_line.startswith('  '):  # 2-space indent
                    # Process cipher in this line
                    def decrypt_match(match):
                        cipher = match.group(0)
                        # Extract base64
                        b64 = re.sub(r"^['\"]?{cipher}|['\"]?$", "", cipher)
                        
                        # SIMULATED DECRYPTION
                        decrypted = "DecryptedSecretValue"
                        
                        # Quote if needed
                        quoted = quote_for_yaml(decrypted)
                        return quoted
                    
                    processed = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", decrypt_match, next_line)
                    result.append(processed)
                    i += 1
                else:
                    # Not indented anymore - end of block
                    break
        else:
            # Regular line - process ciphers normally
            def decrypt_normal(match):
                cipher = match.group(0)
                b64 = re.sub(r"^['\"]?{cipher}|['\"]?$", "", cipher)
                decrypted = "DecryptedSecret"
                quoted = quote_for_yaml(decrypted)
                return quoted
            
            processed = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", decrypt_normal, line)
            result.append(processed)
            i += 1
    
    return '\n'.join(result)


print("=== Test 1: Single cipher in |- block ===")
yaml1 = """password: |-
  {cipher}test=="""
result1 = process_ciphers_in_block(yaml1, "key")
print(f"Result:\n{result1}")
parsed1 = yaml.safe_load(result1)
print(f"Parsed: {repr(parsed1['password'])}\n")

print("=== Test 2: Multiple ciphers in same block ===")
yaml2 = """config: |-
  host={cipher}host==
  port={cipher}port=="""
result2 = process_ciphers_in_block(yaml2, "key")
print(f"Result:\n{result2}")
parsed2 = yaml.safe_load(result2)
print(f"Parsed: {repr(parsed2['config'])}\n")

print("=== Test 3: Cipher with both quotes in value ===")
yaml3 = """command: |-
  {cipher}cmd=="""

# Override decryption for this test
def decrypt_quotes(match):
    return "  'echo \"hello\"'"  # Return with proper indentation and quoting

result3 = re.sub(r"""[']{0,1}\{cipher\}[^}'"]+[']{0,1}""", decrypt_quotes, yaml3)
print(f"Result:\n{result3}")
parsed3 = yaml.safe_load(result3)
print(f"Parsed: {repr(parsed3['command'])}\n")

print("=== Test 4: Mixed - inline and block ciphers ===")
yaml4 = """password: "{cipher}inline=="
connection: |-
  host={cipher}host==
  port={cipher}port=="""

result4 = process_ciphers_in_block(yaml4, "key")
print(f"Result:\n{result4}")
parsed4 = yaml.safe_load(result4)
print(f"Parsed password: {repr(parsed4['password'])}")
print(f"Parsed connection: {repr(parsed4['connection'])}\n")
