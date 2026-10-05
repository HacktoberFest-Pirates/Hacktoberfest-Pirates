"""
Gemma 2 Fine-Tuning Script for PII Detection (LoRA)
Requires: NVIDIA GPU, Unsloth, PyTorch
Usage for Hackathon Judges: This script demonstrates how we parameter-efficiently 
fine-tune (PEFT) Gemma 2b on a custom PII dataset to extract NLP entities.
"""

import os
from unsloth import FastLanguageModel
from datasets import load_dataset
from trl import SFTTrainer
from transformers import TrainingArguments

# 1. Load the base Gemma 2 2b model with Unsloth optimization (4-bit quantization)
max_seq_length = 2048
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="unsloth/gemma-2b-it",
    max_seq_length=max_seq_length,
    dtype=None,
    load_in_4bit=True,
)

# 2. Attach LoRA Adapters (Parameter-Efficient Fine-Tuning)
# This trains only 1-2% of the model's weights, making it incredibly fast.
model = FastLanguageModel.get_peft_model(
    model,
    r=16, # Rank
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_alpha=16,
    lora_dropout=0,
    bias="none",
    use_gradient_checkpointing="unsloth",
    random_state=3407,
)

# 3. Load our custom PII dataset
# In a real environment, this would be a JSONL file with thousands of examples
# format: "Extract PII from: {text}" -> "{"entities": [{"type": "PERSON", "value": "Vedant Gophane"}]}"
dataset = load_dataset("json", data_files="pii_training_data.jsonl", split="train")

def formatting_prompts_func(examples):
    inputs = examples["text"]
    outputs = examples["pii_json"]
    texts = []
    for input_text, output_json in zip(inputs, outputs):
        prompt = f"Extract PII from the following text and output JSON.\nText: {input_text}\nOutput: {output_json}<eos>"
        texts.append(prompt)
    return { "text" : texts, }

dataset = dataset.map(formatting_prompts_func, batched=True)

# 4. Train the Model
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=max_seq_length,
    args=TrainingArguments(
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        warmup_steps=5,
        max_steps=60, # For the hackathon demo, we train 60 steps
        learning_rate=2e-4,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=1,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="linear",
        seed=3407,
        output_dir="outputs",
    ),
)

trainer.train()

# 5. Save the Fine-Tuned LoRA Adapter
model.save_pretrained("gemma-2b-pii-lora")
tokenizer.save_pretrained("gemma-2b-pii-lora")

print("Fine-tuning complete! LoRA adapters saved.")
