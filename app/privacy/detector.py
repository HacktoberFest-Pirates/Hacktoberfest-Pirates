from typing import List
from .schemas import PIIEntity
from .regex_detector import RegexDetector
from .gemma_detector import GemmaDetector
from .entity_merger import merge_entities

class PIIDetector:
    def __init__(self, use_mock_gemma: bool = False):
        self.regex_detector = RegexDetector()
        self.gemma_detector = GemmaDetector(use_mock=use_mock_gemma)

    def detect(self, text: str) -> List[PIIEntity]:
        # 1. Deterministic Detection
        regex_entities = self.regex_detector.detect(text)
        
        # 2. Contextual Detection
        gemma_entities = self.gemma_detector.detect(text)
        
        # 3. Merge and deduplicate
        all_entities = regex_entities + gemma_entities
        
        return merge_entities(all_entities)
