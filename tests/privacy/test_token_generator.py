from app.privacy.token_generator import generate_token
from app.privacy.schemas import EntityType

def test_generate_token():
    t1 = generate_token(EntityType.EMAIL)
    t2 = generate_token(EntityType.EMAIL)
    assert t1 != t2
    assert t1.startswith("<EMAIL_")
    assert t1.endswith(">")

def test_mock_token():
    t1 = generate_token(EntityType.EMAIL, use_mock=True, original_value="test")
    t2 = generate_token(EntityType.EMAIL, use_mock=True, original_value="test")
    assert t1 == t2
