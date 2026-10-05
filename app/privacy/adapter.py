import logging
from typing import Optional

from app.security.interfaces import Decision, SecurityModule, SecurityResult
from app.observability.service import observability
from app.observability.schemas import EventType
from app.privacy.engine import create_privacy_engine, PrivacyEngine

logger = logging.getLogger(__name__)

class PrivacySecurityModule(SecurityModule):
    """Adapter bridging the PrivacyEngine to the SecurityPipeline."""
    
    def __init__(self):
        self.engine: PrivacyEngine = create_privacy_engine()
        
    @property
    def name(self) -> str:
        return "privacy-engine"

    async def inspect(self, content: str, context: dict) -> SecurityResult:
        request_id = context.get("request_id")
        user_id = context.get("user_id") or "unknown"
        tenant_id = context.get("tenant_id") or "unknown"
        
        logger.info(f"Sanitize called with user_id={user_id}, tenant_id={tenant_id}")
        from app.privacy.schemas import SanitizeRequest
        req = SanitizeRequest(request_id=request_id, user_id=user_id, tenant_id=tenant_id, text=content)
        result = self.engine.sanitizer.sanitize(req)
        
        # We need to tell the observability dashboard about detections (via context.detections)
        if "detections" in context and result.detected_entity_count > 0:
            for etype in result.detected_entity_types:
                context["detections"].append({"type": "pii", "subtype": etype})
            
            # Emit one event per exact entity found, so dashboard counters are perfectly accurate!
            for entity in result.entities:
                observability.record_event(EventType.PII_DETECTED, request_id, source=self.name, category=entity.entity_type.value, severity="medium")
                observability.record_event(EventType.PLACEHOLDER_CREATED, request_id, source=self.name, severity="low")
                observability.record_event(EventType.SENSITIVE_DATA_REDACTED, request_id, source=self.name, severity="low")
                
        decision = Decision.MODIFY if result.detected_entity_count > 0 else Decision.ALLOW
        
        return SecurityResult(
            decision=decision,
            module_name=self.name,
            reason=f"Detected {result.detected_entity_count} entities.",
            modified_content=result.sanitized_text,
            metadata={
                "detected_entity_count": result.detected_entity_count,
                "detected_entity_types": [e.value for e in result.detected_entity_types],
            }
        )

    def restore(self, request_id: str, content: str, user_id: Optional[str] = None, tenant_id: Optional[str] = None) -> str:
        logger.info(f"Restore called with user_id={user_id}, tenant_id={tenant_id}"); restored = self.engine.restore(content, request_id, user_id or "unknown", tenant_id or "unknown")
        for _ in range(restored.restoration_count):
            observability.record_event(EventType.PLACEHOLDER_RESTORED, request_id, source=self.name, severity="low")
        return restored.restored_text
        
    def clear_mapping(self, request_id: str, user_id: Optional[str] = None, tenant_id: Optional[str] = None) -> None:
        self.engine.cleanup(request_id, user_id or "unknown", tenant_id or "unknown")






