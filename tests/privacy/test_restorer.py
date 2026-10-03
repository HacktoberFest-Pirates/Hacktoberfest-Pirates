from app.privacy.restorer import Restorer
from app.privacy.schemas import RestoreRequest
from app.privacy.vault import vault

def test_restorer():
    vault.create_request_scope("r_restore", "u1", "t1")
    vault.store_mapping("r_restore", "u1", "t1", "<EMAIL_TEST12>", "test@test.com")
    
    restorer = Restorer()
    req = RestoreRequest(
        request_id="r_restore",
        user_id="u1",
        tenant_id="t1",
        text="The email is <EMAIL_TEST12>."
    )
    
    res = restorer.restore(req)
    assert "test@test.com" in res.restored_text
    assert "<EMAIL_TEST12>" not in res.restored_text
    assert res.restoration_count == 1
