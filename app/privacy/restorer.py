import re
from .schemas import RestoreRequest, RestoreResponse
from .vault import vault
from .exceptions import VaultError

class Restorer:
    def restore(self, request: RestoreRequest) -> RestoreResponse:
        text = request.text
        if not text:
            return RestoreResponse(
                request_id=request.request_id,
                restored_text="",
                restoration_count=0,
                status="CLEAN"
            )
            
        token_pattern = re.compile(r'<[A-Z_]+_[A-Z0-9]+>')
        
        restored_text = text
        restoration_count = 0
        
        unique_tokens = set(token_pattern.findall(text))
        
        for token in unique_tokens:
            try:
                original_value = vault.get_value_for_token(
                    request.request_id, request.user_id, request.tenant_id, token
                )
                if original_value:
                    restored_text = restored_text.replace(token, original_value)
                    restoration_count += 1
            except VaultError:
                pass
                
        status = "RESTORED" if restoration_count > 0 else "CLEAN"
        
        return RestoreResponse(
            request_id=request.request_id,
            restored_text=restored_text,
            restoration_count=restoration_count,
            status=status
        )
