from app.privacy.regex_detector import RegexDetector
from app.privacy.schemas import EntityType

def test_detect_email():
    detector = RegexDetector()
    entities = detector.detect("My email is rahul.sharma@gmail.com.")
    
    # We might have matches for other types if they accidentally overlap, but we expect 1 email
    emails = [e for e in entities if e.entity_type == EntityType.EMAIL]
    assert len(emails) == 1
    assert emails[0].original_value == "rahul.sharma@gmail.com"

def test_detect_indian_phone():
    detector = RegexDetector()
    entities = detector.detect("Call me at 9876543210 or +919988776655.")
    
    phones = [e for e in entities if e.entity_type == EntityType.INDIAN_PHONE]
    assert len(phones) >= 1
    assert any(e.original_value == "9876543210" for e in phones)

def test_detect_pan():
    detector = RegexDetector()
    entities = detector.detect("My PAN is ABCDE1234F")
    
    pans = [e for e in entities if e.entity_type == EntityType.PAN]
    assert len(pans) == 1
    assert pans[0].original_value == "ABCDE1234F"
