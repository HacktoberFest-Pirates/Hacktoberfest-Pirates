import re

# Verhoeff algorithm components
d = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

p = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

def _verhoeff_checksum(num_str: str) -> bool:
    c = 0
    reversed_num = num_str[::-1]
    for i, n in enumerate(reversed_num):
        c = d[c][p[i % 8][int(n)]]
    return c == 0

def validate_aadhaar(aadhaar: str) -> bool:
    normalized = re.sub(r'[\s-]', '', aadhaar)
    if len(normalized) != 12 or not normalized.isdigit():
        return False
    # Reject dummy repeating values
    if len(set(normalized)) == 1:
        return False
    return _verhoeff_checksum(normalized)

def validate_pan(pan: str) -> bool:
    # Expected Indian PAN structure: 5 letters, 4 digits, 1 letter
    pattern = re.compile(r'^[A-Z]{5}[0-9]{4}[A-Z]$', re.IGNORECASE)
    return bool(pattern.match(pan))

def validate_email(email: str) -> bool:
    pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return bool(pattern.match(email))

def validate_indian_phone(phone: str) -> bool:
    normalized = re.sub(r'[\s\-\(\)]', '', phone)
    if normalized.startswith('+91'):
        normalized = normalized[3:]
    elif normalized.startswith('91') and len(normalized) == 12:
        normalized = normalized[2:]
    
    if len(normalized) != 10 or not normalized.isdigit():
        return False
    
    # Typically Indian mobile numbers start with 6-9
    if normalized[0] not in '6789':
        return False
        
    return True

def validate_bank_account(account: str) -> bool:
    normalized = re.sub(r'[\s-]', '', account)
    # Bank accounts vary from 9 to 18 digits in India typically
    if not normalized.isdigit():
        return False
    if len(normalized) < 9 or len(normalized) > 18:
        return False
    # Check for repeating dummy characters
    if len(set(normalized)) == 1:
        return False
    return True
