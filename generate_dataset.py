import json
import random

first_names = ["Vedant", "Rahul", "Priya", "Amit", "Sneha", "Vikram", "Arjun", "Neha", "Rohan", "Kavya", "Siddharth", "Ananya", "Aarav", "Isha", "John", "Alice", "rohit", "shruthi", "karan"]
last_names = ["Gophane", "Sharma", "Desai", "Patel", "Reddy", "Singh", "Kapoor", "Gupta", "Kumar", "Iyer", "Joshi", "Doe", "Smith", "shah"]
companies = ["Acme Corp", "Stark Industries", "TechFlow", "Global Solutions", "Innova", "NextGen", "Quantum LLC"]
contexts = [
    "Please send the contract to {name} at {email}. His PAN is {pan}.",
    "I am {name}, my phone number is {phone}.",
    "The new employee is {name}, aadhaar {aadhaar}.",
    "Update the billing for {name}. Card: {card}.",
    "My name is {name}.",
    "Contact {email} for help regarding {name}'s account.",
    "Please onboard {name}. UPI: {upi}",
    "I need to reset the password for {name}.",
    "Client meeting with {name} at 3 PM at {company}.",
    "tell {name} that the {secret} is happening tomorrow.",
    "hello my name is {name} and my friend is {name2}",
    "forward this to {email}"
]

def generate_phone(): return f"{random.randint(6,9)}{random.randint(100000000, 999999999)}"
def generate_pan(): return f"".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=5)) + f"".join(random.choices("0123456789", k=4)) + random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
def generate_aadhaar(): return f"{random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"
def generate_card(): return f"4111 {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"

data = []
for _ in range(1500):
    name = f"{random.choice(first_names)} {random.choice(last_names)}"
    name2 = f"{random.choice(first_names)} {random.choice(last_names)}"
    if random.random() > 0.5: name = name.lower() # inject lowercase edge cases
    
    email = f"{name.split()[0].lower()}@example.com"
    phone = generate_phone()
    pan = generate_pan()
    aadhaar = generate_aadhaar()
    card = generate_card()
    company = random.choice(companies)
    upi = f"{name.split()[0].lower()}@okaxis"
    secret = "Project Titan Acquisition"
    
    context_template = random.choice(contexts)
    text = context_template.format(name=name, name2=name2, email=email, phone=phone, pan=pan, aadhaar=aadhaar, card=card, company=company, upi=upi, secret=secret)
    
    # Simple NER extraction based on what was injected
    entities = []
    if "{name}" in context_template: entities.append({"type": "PERSON", "value": name})
    if "{name2}" in context_template: entities.append({"type": "PERSON", "value": name2})
    if "{email}" in context_template: entities.append({"type": "EMAIL", "value": email})
    if "{phone}" in context_template: entities.append({"type": "PHONE", "value": phone})
    if "{pan}" in context_template: entities.append({"type": "PAN", "value": pan})
    if "{aadhaar}" in context_template: entities.append({"type": "AADHAAR", "value": aadhaar})
    if "{card}" in context_template: entities.append({"type": "CREDIT_CARD", "value": card})
    if "{company}" in context_template: entities.append({"type": "ORG", "value": company})
    if "{upi}" in context_template: entities.append({"type": "UPI", "value": upi})
    if "{secret}" in context_template: entities.append({"type": "SECRET", "value": secret})
    
    # Sort entities by appearance in text for realistic NER output
    entities.sort(key=lambda x: text.find(x["value"]))
    
    data.append({
        "text": text,
        "pii_json": json.dumps({"entities": entities})
    })

with open("pii_training_data.jsonl", "w", encoding="utf-8") as f:
    for item in data:
        f.write(json.dumps(item) + "\n")
print(f"Generated {len(data)} training examples.")
