from app.privacy.entity_merger import merge_entities
from app.privacy.schemas import PIIEntity, EntityType

def test_merge_identical():
    e1 = PIIEntity(entity_type=EntityType.PERSON, original_value="Rahul", start=0, end=5, confidence=0.9, detection_source="gemma")
    e2 = PIIEntity(entity_type=EntityType.PERSON, original_value="Rahul", start=0, end=5, confidence=1.0, detection_source="regex")
    merged = merge_entities([e1, e2])
    assert len(merged) == 1
    assert merged[0].detection_source == "regex"

def test_merge_overlapping():
    e1 = PIIEntity(entity_type=EntityType.PERSON, original_value="Rahul Sharma", start=0, end=12, confidence=0.9, detection_source="gemma")
    e2 = PIIEntity(entity_type=EntityType.PERSON, original_value="Rahul", start=0, end=5, confidence=0.9, detection_source="gemma")
    merged = merge_entities([e1, e2])
    assert len(merged) == 1
    assert merged[0].original_value == "Rahul Sharma"
