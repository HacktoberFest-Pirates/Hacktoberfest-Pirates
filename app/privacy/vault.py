import time
import threading
from typing import Dict, Optional
from .exceptions import VaultError
from .config import settings

class RequestScope:
    def __init__(self, request_id: str, user_id: str, tenant_id: str):
        self.request_id = request_id
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.created_at = time.time()
        # token -> original_value
        self.token_to_value: Dict[str, str] = {}
        # original_value -> token
        self.value_to_token: Dict[str, str] = {}
        self.lock = threading.Lock()

class Vault:
    def __init__(self):
        # request_id -> RequestScope
        self.scopes: Dict[str, RequestScope] = {}
        self.vault_lock = threading.Lock()
        
    def create_request_scope(self, request_id: str, user_id: str, tenant_id: str) -> None:
        with self.vault_lock:
            self.scopes[request_id] = RequestScope(request_id, user_id, tenant_id)
            
    def store_mapping(self, request_id: str, user_id: str, tenant_id: str, token: str, original_value: str) -> None:
        scope = self._get_scope(request_id, user_id, tenant_id)
        with scope.lock:
            scope.token_to_value[token] = original_value
            scope.value_to_token[original_value] = token
            
    def get_token_for_value(self, request_id: str, user_id: str, tenant_id: str, original_value: str) -> Optional[str]:
        scope = self._get_scope(request_id, user_id, tenant_id)
        with scope.lock:
            return scope.value_to_token.get(original_value)
            
    def get_value_for_token(self, request_id: str, user_id: str, tenant_id: str, token: str) -> Optional[str]:
        scope = self._get_scope(request_id, user_id, tenant_id)
        with scope.lock:
            return scope.token_to_value.get(token)

    def delete_request_scope(self, request_id: str, user_id: str, tenant_id: str) -> None:
        with self.vault_lock:
            scope = self.scopes.get(request_id)
            if scope:
                if scope.user_id != user_id or scope.tenant_id != tenant_id:
                    raise VaultError("Unauthorized deletion attempt")
                del self.scopes[request_id]

    def _get_scope(self, request_id: str, user_id: str, tenant_id: str) -> RequestScope:
        with self.vault_lock:
            scope = self.scopes.get(request_id)
        if not scope:
            raise VaultError(f"No scope found for request_id: {request_id}")
        if scope.user_id != user_id or scope.tenant_id != tenant_id:
            raise VaultError("Cross-tenant or cross-user access attempt")
        return scope
        
    def cleanup_expired(self) -> None:
        now = time.time()
        to_delete = []
        with self.vault_lock:
            for req_id, scope in self.scopes.items():
                if now - scope.created_at > settings.TOKEN_TTL_SECONDS:
                    to_delete.append(req_id)
            for req_id in to_delete:
                del self.scopes[req_id]

# Singleton instance for MVP
vault = Vault()
