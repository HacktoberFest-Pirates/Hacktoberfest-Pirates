import re
from typing import List
from .schemas import PIIEntity, EntityType
from .validators import (
    validate_email,
    validate_indian_phone,
    validate_aadhaar,
    validate_pan,
    validate_bank_account
)

class RegexDetector:
    def __init__(self):
        # Compiled regex patterns
        self.patterns = {
            EntityType.EMAIL: re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            EntityType.PHONE: re.compile(r'\b(?:\+?\d{1,3}[\s-]?)?(?:\d{5}[\s-]?\d{5}|\d{10}|\d{3}[\s-]?\d{3}[\s-]?\d{4})\b'),
            EntityType.AADHAAR: re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
            EntityType.PAN: re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', re.IGNORECASE),
            EntityType.CARD: re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'),
            EntityType.CVV: re.compile(r'\b\d{3,4}\b'),
            EntityType.UPI_ID: re.compile(r'\b[a-zA-Z0-9.\-_]{2,256}@(ybl|okicici|oksbi|okhdfc|okaxis|paytm|apl|ibl|axl|upi)\b', re.IGNORECASE),
            EntityType.IFSC: re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', re.IGNORECASE),
            EntityType.BANK_ACCOUNT: re.compile(r'\b\d{9,18}\b'),
            EntityType.PINCODE: re.compile(r'\b[1-9][0-9]{5}\b'),
            EntityType.IP: re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            EntityType.MAC: re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'),
            EntityType.URL: re.compile(r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)'),
            EntityType.API_KEY: re.compile(r'\b(?:sk|pk)_[a-zA-Z0-9]{20,}\b'),
            EntityType.JWT: re.compile(r'\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b'),
            EntityType.AWS_KEY: re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
            EntityType.UUID: re.compile(r'\b[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}\b'),
            EntityType.PASSPORT: re.compile(r'\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b'),
            EntityType.VEHICLE_REG: re.compile(r'\b[A-Z]{2}\s?\d{2}\s?[A-Z]{1,2}\s?\d{4}\b', re.IGNORECASE),
            EntityType.DOB: re.compile(r'\b\d{2}[/.-]\d{2}[/.-]\d{4}\b'),
        }
        
        self.validators = {
            EntityType.EMAIL: validate_email,
            EntityType.AADHAAR: validate_aadhaar,
            EntityType.PAN: validate_pan,
            EntityType.BANK_ACCOUNT: validate_bank_account
        }

    def detect(self, text: str) -> List[PIIEntity]:
        entities = []
        
        for entity_type, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                value = match.group()
                
                # Apply validation if it exists for the entity type
                validator = self.validators.get(entity_type)
                if validator and not validator(value):
                    continue
                
                entities.append(
                    PIIEntity(
                        entity_type=entity_type,
                        original_value=value,
                        start=match.start(),
                        end=match.end(),
                        confidence=1.0,  # Regex detections are high confidence if they pass validation
                        detection_source="regex"
                    )
                )
                
        return entities
