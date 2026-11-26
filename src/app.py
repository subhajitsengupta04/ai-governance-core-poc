import openai

client = openai.OpenAI()

def health_check():
    return {"status": "ok"}