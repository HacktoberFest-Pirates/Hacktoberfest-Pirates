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
            EntityType.INDIAN_PHONE: re.compile(r'(?:(?:\+|0{0,2})91[\s-]?)?[6-9]\d{9}\b'),
            EntityType.AADHAAR: re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
            EntityType.PAN: re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', re.IGNORECASE),
            EntityType.INDIAN_PINCODE: re.compile(r'\b[1-9][0-9]{5}\b'),
            EntityType.BANK_ACCOUNT: re.compile(r'\b\d{9,18}\b')
        }
        
        self.validators = {
            EntityType.EMAIL: validate_email,
            EntityType.INDIAN_PHONE: validate_indian_phone,
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
