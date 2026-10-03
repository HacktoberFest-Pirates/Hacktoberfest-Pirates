from app.privacy.engine import create_privacy_engine
from app.privacy.vault import vault

def test_cross_tenant_restoration():
    engine = create_privacy_engine()
    engine.sanitizer.use_mock_tokens = True
    
    req_id = "r_sec1"
    
    sanitized = engine.sanitize("Secret email is a@a.com", req_id, "user_a", "tenant_a")
    
    # Another tenant tries to restore using the same request_id and token
    restored = engine.restore(sanitized.sanitized_text, req_id, "user_b", "tenant_b")
    
    # Should not restore
    assert "a@a.com" not in restored.restored_text
    assert restored.restoration_count == 0
    
def test_unknown_token():
    engine = create_privacy_engine()
    req_id = "r_sec2"
    engine.sanitize("Dummy text", req_id, "u1", "t1")
    
    # LLM hallucinates a token
    llm_resp = "Here is the hallucinated token <EMAIL_ABCDEF>."
    
    restored = engine.restore(llm_resp, req_id, "u1", "t1")
    
    # Should not crash and should just return it unchanged
    assert "<EMAIL_ABCDEF>" in restored.restored_text
    assert restored.restoration_count == 0
