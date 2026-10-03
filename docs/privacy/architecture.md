# Privacy Engine Architecture

The Privacy Engine is a critical module of the AI Security Proxy, responsible for pseudonymization of Personal Identifiable Information (PII) before sending data to external Large Language Models (LLMs).

## Detection Strategy
1. **Deterministic (Regex) Detection:** Uses pre-compiled regex patterns coupled with strict validators (e.g., Verhoeff checksum for Aadhaar) to detect rigid formats like emails, phones, and national IDs.
2. **Contextual (Gemma 4) Detection:** Fallback or additive detection using local LLM inference to catch contextual information like names and unstructured identifiers.

## Tokenization and Vault
- Tokens are generated using cryptographically secure random strings or hashes (in test mode).
- Mappings between tokens and original values are stored in a request-scoped, isolated in-memory **Vault**.
- The Vault enforces tenant and user isolation. Cross-tenant access throws security exceptions.

## Restoration
- After the external LLM responds, tokens are identified and replaced with the original PII.
- The system only replaces tokens that are valid within the exact request scope.
