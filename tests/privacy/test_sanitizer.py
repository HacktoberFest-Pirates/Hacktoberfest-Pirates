from app.privacy.sanitizer import Sanitizer
from app.privacy.detector import PIIDetector
from app.privacy.schemas import SanitizeRequest

def test_sanitizer():
    detector = PIIDetector(use_mock_gemma=True)
    sanitizer = Sanitizer(detector, use_mock_tokens=True)
    
    req = SanitizeRequest(
        request_id="r1",
        user_id="u1",
        tenant_id="t1",
        text="My email is test@test.com and phone is 9876543210."
    )
    
    res = sanitizer.sanitize(req)
    assert "test@test.com" not in res.sanitized_text
    assert "9876543210" not in res.sanitized_text
    assert res.detected_entity_count >= 2
