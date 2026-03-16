import re

def test_key(h):
    # Step 1: Remove any quotes, colons, and joiners
    cleaned = h.replace('"', '').replace("'", "").replace(':', '').strip()
    
    # Step 2: Extract key if 'Bearer' exists (case insensitive)
    # Handle cases like 'bearer4Sb...' or 'bearer 4Sb...'
    match = re.search(r'(?:bearer\s*)?([a-zA-Z0-9]{10,})', cleaned, re.IGNORECASE)
    if match:
        return match.group(1)
    return cleaned

headers = [
    'Bearer 4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6',
    '"Bearer 4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6"',
    'Bearer Bearer 4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6',
    '4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6',
    'bearer:4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6',
    "'Bearer 4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6'"
]

expected = "4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6"

print("--- REGEX API KEY EXTRACTION TEST ---")
all_passed = True
for h in headers:
    result = test_key(h)
    passed = result == expected
    print(f"Input: {h: <50} | Result: {result[:10]}... | Passed: {passed}")
    if not passed: all_passed = False

if all_passed:
    print("\nSUCCESS: All API key formats are handled correctly!")
else:
    print("\nFAILED: Some formats failed.")
    exit(1)
