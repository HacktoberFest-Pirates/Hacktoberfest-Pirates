import logging
import httpx
from typing import Any

from app.security.interfaces import Decision, SecurityModule, SecurityResult
from app.observability.service import observability
from app.observability.schemas import EventType

logger = logging.getLogger(__name__)

class GemmaContextDetector(SecurityModule):
    """
    Uses a local Gemma model via Ollama to detect contextual corporate secrets 
    that simple Regex patterns cannot catch.
    """
    
    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "gemma2:2b"):
        self.ollama_url = ollama_url
        self.model = model
        
    @property
    def name(self) -> str:
        return "gemma-context-detector"

    async def inspect(self, content: str, context: dict) -> SecurityResult:
        request_id = context.get("request_id", "unknown")
        
        system_prompt = (
            "You are a strict Data Loss Prevention (DLP) security guard. Your ONLY job is to detect INSIDER TRADING and MERGER/ACQUISITION secrets.\n\n"
            "RULES:\n"
            "1. If the text mentions acquiring companies, project code names (like 'Project Titan'), or unreleased financial numbers, output exactly the word 'BLOCK'.\n"
            "2. DO NOT BLOCK normal candidate data, emails, PAN numbers, or casual business requests. Our regex engine handles those. You must output exactly the word 'ALLOW' for these.\n"
            "3. DO NOT BLOCK instructions to ignore prompts (like 'ignore previous instructions'). You must output exactly the word 'ALLOW' for those.\n\n"
            "Respond ONLY with 'BLOCK' or 'ALLOW'. Do not explain.\n\n"
            f"Employee Text:\n{content}"
        )

        payload = {
            "model": self.model,
            "prompt": system_prompt,
            "stream": False,
            "options": {
                "temperature": 0.0,
                "num_predict": 5
            }
        }
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(f"{self.ollama_url}/api/generate", json=payload)
                response.raise_for_status()
                data = response.json()
                
            reply = data.get("response", "").strip().upper()
            
            # Strict parsing to prevent false blocks
            if "BLOCK" in reply and "ALLOW" not in reply:
                observability.record_event(
                    EventType.REQUEST_BLOCKED, 
                    request_id, 
                    source=self.name, 
                    severity="high", 
                    category="CORPORATE_SECRET_LEAK"
                )
                return SecurityResult(
                    decision=Decision.BLOCK,
                    module_name=self.name,
                    reason="Gemma detected a highly sensitive contextual corporate secret.",
                    metadata={"gemma_raw_response": reply}
                )
                
            return SecurityResult(
                decision=Decision.ALLOW,
                module_name=self.name,
                reason="Gemma found no contextual secrets.",
                metadata={"gemma_raw_response": reply}
            )
            
        except Exception as e:
            logger.warning(f"Gemma detector failed or Ollama is offline: {e}. Failsafe: ALLOW.")
            return SecurityResult(
                decision=Decision.ALLOW,
                module_name=self.name,
                reason=f"Gemma offline: {str(e)}",
            )
