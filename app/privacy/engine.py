from .schemas import SanitizeRequest, SanitizeResponse, RestoreRequest, RestoreResponse
from .detector import PIIDetector
from .sanitizer import Sanitizer
from .restorer import Restorer
from .vault import vault

class PrivacyEngine:
    def __init__(self, use_mock_gemma: bool = False, use_mock_tokens: bool = False):
        self.detector = PIIDetector(use_mock_gemma=use_mock_gemma)
        self.sanitizer = Sanitizer(self.detector, use_mock_tokens=use_mock_tokens)
        self.restorer = Restorer()
        
    def sanitize(self, text: str, request_id: str, user_id: str, tenant_id: str) -> SanitizeResponse:
        req = SanitizeRequest(
            request_id=request_id,
            user_id=user_id,
            tenant_id=tenant_id,
            text=text
        )
        result = self.sanitizer.sanitize(req)
        
        return SanitizeResponse(
            request_id=result.request_id,
            sanitized_text=result.sanitized_text,
            detected_entity_count=result.detected_entity_count,
            detected_entity_types=result.detected_entity_types,
            status=result.status
        )
        
    def restore(self, text: str, request_id: str, user_id: str, tenant_id: str) -> RestoreResponse:
        req = RestoreRequest(
            request_id=request_id,
            user_id=user_id,
            tenant_id=tenant_id,
            text=text
        )
        return self.restorer.restore(req)
        
    def cleanup(self, request_id: str, user_id: str, tenant_id: str) -> None:
        try:
            vault.delete_request_scope(request_id, user_id, tenant_id)
        except Exception:
            # We don't want cleanup to fail the main process if scope is missing
            pass

def create_privacy_engine() -> PrivacyEngine:
    return PrivacyEngine()
