from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from enum import Enum

class EntityType(str, Enum):
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    INDIAN_PHONE = "INDIAN_PHONE"
    AADHAAR = "AADHAAR"
    PAN = "PAN"
    INDIAN_PINCODE = "INDIAN_PINCODE"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    UNKNOWN = "UNKNOWN"

class PIIEntity(BaseModel):
    entity_type: EntityType
    original_value: str
    start: int
    end: int
    confidence: float
    detection_source: str = "regex"

class SanitizeRequest(BaseModel):
    request_id: str
    user_id: str
    tenant_id: str
    text: str

class SanitizeResponse(BaseModel):
    request_id: str
    sanitized_text: str
    detected_entity_count: int
    detected_entity_types: List[EntityType]
    status: str

class RestoreRequest(BaseModel):
    request_id: str
    user_id: str
    tenant_id: str
    text: str

class RestoreResponse(BaseModel):
    request_id: str
    restored_text: str
    restoration_count: int
    status: str

class PrivacyResult(BaseModel):
    request_id: str
    sanitized_text: str
    entities: List[PIIEntity]
    detected_entity_count: int
    detected_entity_types: List[EntityType]
    status: str
