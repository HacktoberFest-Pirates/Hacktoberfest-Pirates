import secrets
import hashlib
from .config import settings
from .schemas import EntityType

def generate_token(entity_type: EntityType, use_mock: bool = False, original_value: str = "") -> str:
    if use_mock:
        # Deterministic generation for tests
        h = hashlib.sha256(original_value.encode()).hexdigest()[:settings.TOKEN_ID_LENGTH].upper()
        return f"<{entity_type.value}_{h}>"
    
    # Cryptographically secure random token
    length_bytes = max(1, settings.TOKEN_ID_LENGTH // 2)
    random_hex = secrets.token_hex(length_bytes).upper()
    
    # Ensure it's exactly the configured length
    if len(random_hex) < settings.TOKEN_ID_LENGTH:
        random_hex = random_hex.ljust(settings.TOKEN_ID_LENGTH, '0')
    elif len(random_hex) > settings.TOKEN_ID_LENGTH:
        random_hex = random_hex[:settings.TOKEN_ID_LENGTH]
        
    return f"<{entity_type.value}_{random_hex}>"
