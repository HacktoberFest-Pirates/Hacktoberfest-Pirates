"""Unique ID generation utilities."""

import uuid


def generate_request_id() -> str:
    """Generate a unique request identifier.

    Returns:
        A string like 'req_a1b2c3d4'.
    """
    return f"req_{uuid.uuid4().hex[:8]}"


def generate_event_id() -> str:
    """Generate a unique event identifier.

    Returns:
        A string like 'evt_a1b2c3d4'.
    """
    return f"evt_{uuid.uuid4().hex[:8]}"
