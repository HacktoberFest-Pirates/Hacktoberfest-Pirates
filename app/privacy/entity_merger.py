from typing import List
from .schemas import PIIEntity

def merge_entities(entities: List[PIIEntity]) -> List[PIIEntity]:
    if not entities:
        return []
        
    # Sort entities primarily by start index, then by length (longest first)
    sorted_entities = sorted(entities, key=lambda e: (e.start, -(e.end - e.start)))
    
    merged = []
    current = sorted_entities[0]
    
    for next_entity in sorted_entities[1:]:
        # If there's an overlap
        if next_entity.start < current.end:
            # Case 1: Identical span, prefer regex source over gemma
            if next_entity.start == current.start and next_entity.end == current.end:
                if next_entity.detection_source == "regex" and current.detection_source != "regex":
                    current = next_entity
            # Case 2: next_entity is fully contained within current, ignore next_entity
            elif next_entity.end <= current.end:
                pass
            # Case 3: Partial overlap (end is greater).
            else:
                # To avoid complex partial merging, we keep the earlier/longer one (current).
                pass
        else:
            merged.append(current)
            current = next_entity
            
    merged.append(current)
    return merged
