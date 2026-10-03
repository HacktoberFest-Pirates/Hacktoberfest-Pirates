from app.privacy.engine import create_privacy_engine

def test_full_flow():
    engine = create_privacy_engine()
    # Let's override to use mock for tokens & gemma for predictable tests
    engine.detector.gemma_detector.use_mock = True
    engine.sanitizer.use_mock_tokens = True
    
    text = "Rahul Sharma's email is test@example.com."
    req_id = "req_123"
    user_id = "u_1"
    tenant_id = "t_1"
    
    sanitized = engine.sanitize(text, req_id, user_id, tenant_id)
    
    assert "test@example.com" not in sanitized.sanitized_text
    assert "Rahul Sharma" not in sanitized.sanitized_text
    
    restored = engine.restore(sanitized.sanitized_text, req_id, user_id, tenant_id)
    
    assert "test@example.com" in restored.restored_text
    assert "Rahul Sharma" in restored.restored_text
    
    engine.cleanup(req_id, user_id, tenant_id)
