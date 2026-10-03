import logging
from typing import List
from .schemas import SanitizeRequest, SanitizeResponse, PrivacyResult
from .detector import PIIDetector
from .token_generator import generate_token
from .vault import vault

logger = logging.getLogger(__name__)

class Sanitizer:
    def __init__(self, detector: PIIDetector, use_mock_tokens: bool = False):
        self.detector = detector
        self.use_mock_tokens = use_mock_tokens

    def sanitize(self, request: SanitizeRequest) -> PrivacyResult:
        try:
            vault.create_request_scope(request.request_id, request.user_id, request.tenant_id)
        except Exception as e:
            logger.error(f"Failed to create request scope: {e}")
            raise
            
        text = request.text
        if not text:
            return self._empty_result(request)
            
        entities = self.detector.detect(text)
        if not entities:
            return self._empty_result(request)
            
        # We need to replace from the end to the start to not mess up offsets
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        sanitized_text = text
        
        detected_types = set()
        
        for entity in sorted_entities:
            detected_types.add(entity.entity_type)
            
            # Check if this exact value was already tokenized in this request
            existing_token = vault.get_token_for_value(
                request.request_id, request.user_id, request.tenant_id, entity.original_value
            )
            
            if existing_token:
                token = existing_token
            else:
                token = generate_token(entity.entity_type, use_mock=self.use_mock_tokens, original_value=entity.original_value)
                vault.store_mapping(
                    request.request_id, request.user_id, request.tenant_id, token, entity.original_value
                )
                
            # Replace using exact offsets
            sanitized_text = sanitized_text[:entity.start] + token + sanitized_text[entity.end:]
            
        return PrivacyResult(
            request_id=request.request_id,
            sanitized_text=sanitized_text,
            entities=entities,
            detected_entity_count=len(entities),
            detected_entity_types=list(detected_types),
            status="SANITIZED"
        )

    def _empty_result(self, request: SanitizeRequest) -> PrivacyResult:
        return PrivacyResult(
            request_id=request.request_id,
            sanitized_text=request.text,
            entities=[],
            detected_entity_count=0,
            detected_entity_types=[],
            status="CLEAN"
        )
