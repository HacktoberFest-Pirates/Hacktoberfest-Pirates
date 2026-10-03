"""Synthetic demo data. Uses ONLY fake, clearly-synthetic values (no real personal data)."""
from __future__ import annotations

import random
import uuid
from datetime import timedelta
from typing import Optional

from .schemas import utcnow
from .service import ObservabilityService

MODELS = [("openai", "gpt-4o-mini"), ("google", "gemini-2.5-flash"),
          ("local", "gemma"), ("groq", "llama-3.3-70b")]
PII_CATS = ["EMAIL", "PHONE", "PERSON", "ADDRESS", "CREDIT_CARD", "API_KEY", "IP_ADDRESS"]


def generate_demo_data(svc: ObservabilityService, n: int = 150, hours: float = 6.0,
                       seed: Optional[int] = 42) -> int:
    rnd = random.Random(seed)
    now = utcnow()
    for _ in range(n):
        rid = str(uuid.uuid4())
        t = now - timedelta(minutes=rnd.uniform(0, hours * 60))
        step = lambda: (setattr(step, "t", step.t + timedelta(milliseconds=rnd.randint(5, 40))) or step.t)
        step.t = t

        def ev(et, **kw):
            svc.record_event(et, rid, timestamp=step(), **kw)

        scenario = rnd.choices(["normal", "pii", "block", "suspicious", "fail"], [60, 18, 10, 4, 8])[0]
        provider, model = rnd.choice(MODELS)
        ev("REQUEST_RECEIVED", source="proxy")
        if scenario in {"pii", "block"} or (scenario == "suspicious" and rnd.random() < .5):
            cats = rnd.sample(PII_CATS, rnd.randint(1, 3))
            for c in cats:
                n_ent = rnd.randint(1, 3)
                ev("PII_DETECTED", source="pii_detector", category=c, confidence=round(rnd.uniform(.8, .99), 2),
                   decision="REDACT", metadata={"count": n_ent})
                ev("SENSITIVE_DATA_REDACTED", source="redactor", category=c, metadata={"count": n_ent})
                ev("PLACEHOLDER_CREATED", source="placeholder_engine", category=c, metadata={"count": n_ent})
        if scenario in {"block", "suspicious"}:
            decision = "BLOCK" if scenario == "block" else "ALLOW"
            conf = round(rnd.uniform(.9, .99) if scenario == "block" else rnd.uniform(.5, .7), 2)
            ev("PROMPT_INJECTION_DETECTED", source="prompt_guard", severity="high" if scenario == "block" else "medium",
               decision=decision, category="INSTRUCTION_OVERRIDE", confidence=conf)
        if scenario == "block":
            ev("REQUEST_BLOCKED", source="policy_engine", decision="BLOCK",
               metadata={"reason_code": "PROMPT_INJECTION", "latency_ms": rnd.randint(8, 60)})
            continue
        ev("REQUEST_ALLOWED", source="policy_engine", decision="ALLOW")
        ev("LLM_REQUEST_SENT", source="llm_router", metadata={"provider": provider, "model": model})
        base = {"local": 1400, "groq": 450, "openai": 900, "google": 1100}[provider]
        lat = max(80, int(rnd.gauss(base, base * .35)) + (rnd.randint(2000, 5000) if rnd.random() < .04 else 0))
        if scenario == "fail":
            err = rnd.choice(["PROVIDER_TIMEOUT", "RATE_LIMITED", "PROVIDER_5XX"])
            svc.record_llm_call(rid, provider, model, latency_ms=lat, status="error", error_type=err, timestamp=step())
            svc.finalize_request(rid, "failed", latency_ms=lat + 20, error_type=err, timestamp=step())
            continue
        pt, ct = rnd.randint(30, 800), rnd.randint(50, 1500)
        svc.record_llm_call(rid, provider, model, pt, ct, lat,
                            estimated_cost=round((pt * .15 + ct * .6) / 1e6, 6) if provider == "openai" else None,
                            timestamp=step())
        if scenario == "pii":
            ev("PLACEHOLDER_RESTORED", source="placeholder_engine", metadata={"count": rnd.randint(1, 3)})
            ev("RESPONSE_SANITIZED", source="response_guard")
        svc.finalize_request(rid, "completed", latency_ms=lat + rnd.randint(15, 60), timestamp=step())
    svc.flush()
    return n
