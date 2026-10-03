import pytest
from app.privacy.vault import Vault
from app.privacy.exceptions import VaultError

def test_vault_isolation():
    v = Vault()
    v.create_request_scope("req1", "user1", "tenant1")
    v.store_mapping("req1", "user1", "tenant1", "<TOKEN>", "secret")
    
    # Correct access
    assert v.get_value_for_token("req1", "user1", "tenant1", "<TOKEN>") == "secret"
    
    # Wrong request
    with pytest.raises(VaultError):
        v.get_value_for_token("req2", "user1", "tenant1", "<TOKEN>")
        
    # Wrong user
    with pytest.raises(VaultError):
        v.get_value_for_token("req1", "user2", "tenant1", "<TOKEN>")
        
def test_vault_cleanup():
    v = Vault()
    v.create_request_scope("req1", "user1", "tenant1")
    v.delete_request_scope("req1", "user1", "tenant1")
    
    with pytest.raises(VaultError):
        v.get_value_for_token("req1", "user1", "tenant1", "<TOKEN>")
