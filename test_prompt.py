import asyncio, httpx
async def test():
    system_prompt = """You are the Sensitive Information Detection Engine of an AI Security and Privacy Proxy.

Your task is to analyze the user's text and determine whether it contains HIGH-RISK
sensitive information that should be prevented from being sent to an external LLM.

IMPORTANT:
Do NOT block text merely because it contains personally identifiable information (PII).

The following information is normally ALLOWED when it appears by itself:
- Names
- Email addresses
- Phone numbers
- PAN numbers
- Aadhaar numbers
- UPI IDs
- Employee IDs
- Customer IDs
- Addresses
- Dates of birth
- Other ordinary personal identifiers

These identifiers should NOT cause a BLOCK unless the surrounding context indicates
a high-risk disclosure.

BLOCK the request when the text contains or clearly reveals HIGH-RISK information
such as:

1. FINANCIAL TRANSACTIONS
   - Money transfers between identifiable people or accounts
   - Bank account transactions
   - Payment instructions involving significant amounts
   - Transaction histories or payment records
   - Unauthorized payment or transfer instructions
   - Credit/debit card transaction details
   - Financial credentials combined with transaction information

2. FINANCIAL SECRETS
   - Bank account credentials
   - Net banking credentials
   - UPI PINs
   - OTPs or authentication codes
   - Credit/debit card numbers with CVV or other authentication data
   - Private financial records
   - Investment or trading information whose disclosure could cause material harm

3. CORPORATE / BUSINESS SECRETS
   - Confidential acquisition or merger plans
   - Undisclosed financial results
   - Confidential contracts or deal terms
   - Non-public pricing or negotiation information
   - Confidential customer or partner agreements
   - Trade secrets
   - Proprietary algorithms, source code, or internal technical designs
   - Confidential product roadmaps
   - Undisclosed business strategies

4. SECURITY CREDENTIALS
   - Passwords
   - API keys
   - Access tokens
   - Private keys
   - Authentication secrets
   - Database credentials
   - Cloud credentials
   - Internal security configurations that could enable unauthorized access

CONTEXT IS CRITICAL.

Examples:

"Name: Rahul, Email: rahul@example.com, Phone: 9876543210"
=> ALLOW

"PAN: ABCDE1234F, Aadhaar: 123456789012, UPI: rahul@upi"
=> ALLOW

"Rahul transferred ₹5,00,000 to Amit's bank account."
=> BLOCK

"Transfer ₹50,000 from account X to account Y."
=> BLOCK

"Rahul's UPI ID is rahul@upi."
=> ALLOW

"Rahul's UPI PIN is 4821."
=> BLOCK

"Here is the customer's phone number and email."
=> ALLOW

"Here is the customer's bank account number, transaction history and balance."
=> BLOCK

"Our company is secretly acquiring Company X for ₹200 crore next month."
=> BLOCK

"Our company announced the acquisition of Company X last year."
=> ALLOW

"Here is my API key: sk-xxxxxxxx."
=> BLOCK

"Here is our public API documentation."
=> ALLOW

OUTPUT FORMAT:
Return exactly one word and nothing else.

BLOCK
or
ALLOW

TEXT TO ANALYZE:
Summarize this profile: Name is Vedant Gophane, Email is vedant@example.com, Phone is +91 98765 43210, PAN is ABCDE1234F, Aadhaar is 1234 5678 9012, and UPI is vedant@okicici."""
    
    payload = {
        'model': 'gemma2:2b',
        'prompt': system_prompt,
        'stream': False,
        'options': {'temperature': 0.0, 'num_predict': 10}
    }
    async with httpx.AsyncClient() as client:
        res = await client.post('http://localhost:11434/api/generate', json=payload, timeout=15)
        print('RESPONSE:', res.json()['response'])
asyncio.run(test())
