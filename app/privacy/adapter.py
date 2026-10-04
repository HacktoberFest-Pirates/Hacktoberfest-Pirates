import logging
from typing import Optional

from app.security.interfaces import Decision, SecurityModule, SecurityResult
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
        
        logger.info(f"Sanitize called with user_id={user_id}, tenant_id={tenant_id}"); sanitized = self.engine.sanitize(content, request_id, user_id, tenant_id)
        
        # We need to tell the observability dashboard about detections (via context.detections)
        if "detections" in context and sanitized.detected_entity_count > 0:
            for etype in sanitized.detected_entity_types:
                context["detections"].append({"type": "pii", "subtype": etype})
                
        decision = Decision.MODIFY if sanitized.detected_entity_count > 0 else Decision.ALLOW
        
        return SecurityResult(
            decision=decision,
            module_name=self.name,
            reason=f"Detected {sanitized.detected_entity_count} entities.",
            modified_content=sanitized.sanitized_text,
            metadata={
                "detected_entity_count": sanitized.detected_entity_count,
                "detected_entity_types": sanitized.detected_entity_types,
            }
        )

    def restore(self, request_id: str, content: str, user_id: Optional[str] = None, tenant_id: Optional[str] = None) -> str:
        logger.info(f"Restore called with user_id={user_id}, tenant_id={tenant_id}"); restored = self.engine.restore(content, request_id, user_id or "unknown", tenant_id or "unknown")
        return restored.restored_text
        
    def clear_mapping(self, request_id: str, user_id: Optional[str] = None, tenant_id: Optional[str] = None) -> None:
        self.engine.cleanup(request_id, user_id or "unknown", tenant_id or "unknown")




