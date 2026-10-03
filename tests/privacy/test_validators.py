from app.privacy.validators import (
    validate_aadhaar,
    validate_pan,
    validate_email,
    validate_indian_phone,
    validate_bank_account
)

def test_validate_aadhaar():
    # 111111111111 is rejected due to repeating rule
    assert validate_aadhaar("111111111111") == False
    assert validate_aadhaar("1234") == False
    
def test_validate_pan():
    assert validate_pan("ABCDE1234F") == True
    assert validate_pan("12345ABCDE") == False
    assert validate_pan("ABCDE12345") == False
    
def test_validate_email():
    assert validate_email("test@example.com") == True
    assert validate_email("invalid-email") == False

def test_validate_indian_phone():
    assert validate_indian_phone("9876543210") == True
    assert validate_indian_phone("+919876543210") == True
    assert validate_indian_phone("1234567890") == False # starts with 1
    
def test_validate_bank_account():
    assert validate_bank_account("123456789") == True
    assert validate_bank_account("111111111") == False
    assert validate_bank_account("123") == False
