# Known Limitations

## Detection Accuracy
- **False Negatives:** Regex deterministic matching alone will not catch implicitly defined personal information, contextual references, or misspelled structured PII.
- **False Positives:** Non-PII numbers might be incorrectly identified as IDs if they pass basic formatting (although Verhoeff and formatting checks mitigate this).
- **Gemma Contextual Reliability:** If Gemma 4 is used, contextual inference might hallucinate entities or miss subtle PII. The offsets provided by the model may occasionally be misaligned.

## Vault Volatility
- The MVP relies on an **in-memory** `Vault`. Mappings are lost upon application restart.
- For a multi-instance (horizontal scaling) deployment, this approach will fail if sanitization and restoration hit different instances. A distributed store (e.g., Redis) adapter is required for production.

## Pseudonymization vs. Anonymization
- This module implements **reversible pseudonymization**, which reduces risk but is NOT true anonymization.
- Highly contextual data remaining in the prompt might still allow an adversary to re-identify subjects.
- Residual risks remain if a malicious LLM attempts contextual inference around the tokenized gaps.

## LLM-Generated Tokens
- The Restoration engine only restores tokens valid within the current `request_id`. If an LLM fabricates a token, it will safely be ignored.
