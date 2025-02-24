from typing import Any, Dict, List, Optional
import os
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
import snowflake.connector
import requests
import pandas as pd
import generate_jwt
from dotenv import load_dotenv
import json
import time

load_dotenv()

USER = os.getenv("USER")
ACCOUNT = os.getenv("ACCOUNT")
DATABASE = os.getenv("DATABASE")
SCHEMA = os.getenv("SCHEMA")
PASSWORD = os.getenv("PASSWORD")
ANALYST_ENDPOINT = os.getenv("ANALYST_ENDPOINT")
# RSA_PRIVATE_KEY_PATH = os.getenv("RSA_PRIVATE_KEY_PATH")
RSA_PRIVATE_KEY = os.getenv("RSA_PRIVATE_KEY")
STAGE = os.getenv("SEMANTIC_MODEL_STAGE")
FILE = os.getenv("SEMANTIC_MODEL_FILE")
SLACK_APP_TOKEN = os.getenv("SLACK_APP_TOKEN")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
DEBUG = False

# Inicijalizacija Slack aplikacije
app = App(token=SLACK_BOT_TOKEN)

# Memorija razgovora po korisniku
messages_store = {}  
MAX_HISTORY = 5  # Maksimalan broj prethodnih poruka

@app.event("message")
def handle_message_events(ack, body, say):
    ack()
    user_id = body["event"]["user"]
    prompt = body["event"]["text"]

    # Sačuvaj istoriju razgovora
    if user_id not in messages_store:
        messages_store[user_id] = []
    
    # Ograničavanje dužine istorije
    if len(messages_store[user_id]) >= MAX_HISTORY * 2:
        messages_store[user_id] = messages_store[user_id][-MAX_HISTORY * 2:]  # Čuvamo poslednjih 5 interakcija (user + analyst)

    # Dodaj korisničku poruku
    messages_store[user_id].append({"role": "user", "content": [{"type": "text", "text": prompt}]})

    process_analyst_message(user_id, say)

@app.command("/resetmemory")
def reset_memory(ack, body, say):
    ack()
    user_id = body["user_id"]
    if user_id in messages_store:
        del messages_store[user_id]
        say("Your conversation history has been reset.")
    else:
        say("No conversation history found.")

def process_analyst_message(user_id, say) -> Any:
    prompt = messages_store[user_id][-1]["content"][0]["text"]
    say_question(prompt, say)
    response = query_cortex_analyst(user_id)
    content = response["message"]["content"]

    # Dodaj odgovor analitičara u istoriju razgovora
    messages_store[user_id].append({"role": "analyst", "content": content})

    display_analyst_content(content, say)

def say_question(prompt, say):
    say(
        text="Question:",
        blocks=[
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Question: {prompt}",
                }
            },
        ]                
    )
    say(
        text="Snowflake Cortex Analyst is generating a response",
        blocks=[
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "plain_text", "text": "Snowflake Cortex Analyst is generating a response. Please wait..."}
            },
            {"type": "divider"},
        ]
    )

def query_cortex_analyst(user_id) -> Dict[str, Any]:
    messages = messages_store.get(user_id, [])

    request_body = {
        "messages": messages,
        "semantic_model_file": f"@{DATABASE}.{SCHEMA}.{STAGE}/{FILE}",
    }
    
    resp = requests.post(
        url=f"{ANALYST_ENDPOINT}",
        json=request_body,
        headers={
            "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {JWT}",
        },
    )

    request_id = resp.headers.get("X-Snowflake-Request-Id")
    if resp.status_code == 200:
        return {**resp.json(), "request_id": request_id}  
    else:
        raise Exception(f"Failed request (id: {request_id}) with status {resp.status_code}: {resp.text}")

def display_analyst_content(content: List[Dict[str, str]], say=None) -> None:
    if DEBUG:
        print(content)
    for item in content:
        if item["type"] == "sql":
            sql_query = item["statement"]
            say(
                text="Generated SQL:",
                blocks=[
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"```{sql_query}```"
                        }
                    }
                ]
            )
            df = pd.read_sql(sql_query, CONN)
            if df.empty:
                say("Query returned no data.")
            else:
                say(f"Result:\n```{df.to_string(index=False)}```")

def init():
    conn, jwt = None, None
    conn = snowflake.connector.connect(
        user=USER,
        password=PASSWORD,
        account=ACCOUNT
    )
    
    jwt = generate_jwt.JWTGenerator(ACCOUNT, USER, RSA_PRIVATE_KEY).get_token()
    return conn, jwt

# Start app
if __name__ == "__main__":
    CONN, JWT = init()
    if not CONN.rest.token:
        print("Error: Failed to connect to Snowflake! Please check your Snowflake user, password, and account environment variables and try again.")
        quit()
    SocketModeHandler(app, SLACK_APP_TOKEN).start()
