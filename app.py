from typing import Any, Dict, List, Optional
import os
import queue
import threading
import time
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
import snowflake.connector
import requests
import pandas as pd
import generate_jwt
from dotenv import load_dotenv
import json
from datetime import timedelta


load_dotenv()

# 🔹 Loading configuration from ENV variables
USER = os.getenv("USER")
ACCOUNT = os.getenv("ACCOUNT")
DATABASE = os.getenv("DATABASE")
SCHEMA = os.getenv("SCHEMA")
PASSWORD = os.getenv("PASSWORD")
ANALYST_ENDPOINT = os.getenv("ANALYST_ENDPOINT")
RSA_PRIVATE_KEY_PATH = os.getenv("RSA_PRIVATE_KEY_PATH")
RSA_PRIVATE_KEY_PASSPHRASE = os.getenv("RSA_PRIVATE_KEY_PASSPHRASE")  # 🔹 Added
STAGE = os.getenv("SEMANTIC_MODEL_STAGE")
FILE = os.getenv("SEMANTIC_MODEL_FILE")
SLACK_APP_TOKEN = os.getenv("SLACK_APP_TOKEN")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
DEBUG = False

# Initializing the Slack application
app = App(token=SLACK_BOT_TOKEN)

# Conversation memory per user
messages_store = {}  
MAX_HISTORY = 5  # Maximum number of previous messages

# Creating a Queue for Queries
message_queue = queue.Queue()
queue_lock = threading.Lock()

def process_analyst_message(user_id, user_prompt, say):
    """We add the user's request to the queue and inform him about the position in the queue."""
    
    # Save user conversation history
    if user_id not in messages_store:
        messages_store[user_id] = []

    # Limiting the history to the last MAX_HISTORY interactions
    if len(messages_store[user_id]) >= MAX_HISTORY * 2:
        messages_store[user_id] = messages_store[user_id][-MAX_HISTORY * 2:]

    messages_store[user_id].append({"role": "user", "content": [{"type": "text", "text": user_prompt}]})

    queue_position = message_queue.qsize() + 1 
    message_queue.put((user_id, user_prompt, say))
    say(f"✅ Your question has been added to the queue. Position in queue: {queue_position}. Please wait...")

def process_queue():
    """An independent function that takes queries from a queue and processes them one by one."""
    while True:
        user_id, user_prompt, say = message_queue.get() 

        say(f"🤖 Processing question for <@{user_id}>: `{user_prompt}`")

        # Generate response via Cortex Analyst
        response = query_cortex_analyst(user_id)
        content = response["message"]["content"]

        # Save reply to conversation history
        messages_store[user_id].append({"role": "analyst", "content": content})

        # View replies in Slack
        display_analyst_content(content, say)

        message_queue.task_done()  
        time.sleep(1) 

# Starting a background thread that processes the queue
worker_thread = threading.Thread(target=process_queue, daemon=True)
worker_thread.start()

@app.event("message")
def handle_message_events(ack, body, say):
    ack()
    user_id = body["event"]["user"]
    user_prompt = body["event"]["text"]

    # We add the query to the queue
    process_analyst_message(user_id, user_prompt, say)

@app.command("/resetmemory")
def reset_memory(ack, body, say):
    ack()
    user_id = body["user_id"]
    if user_id in messages_store:
        del messages_store[user_id]
        say("Your conversation history has been reset.")
    else:
        say("No conversation history found.")

def query_cortex_analyst(user_id) -> Dict[str, Any]:
    messages = messages_store.get(user_id, [])

    # Check if the last message comes from the user
    if messages and messages[-1]["role"] != "user":
        raise Exception("Snowflake Cortex requires last message to be from the user.")

    # create a new connection before each query
    conn, jwt = init()

    request_body = {
        "messages": messages,  # Use the history
        "semantic_model_file": f"@{DATABASE}.{SCHEMA}.{STAGE}/{FILE}",
    }
    
    resp = requests.post(
        url=f"{ANALYST_ENDPOINT}",
        json=request_body,
        headers={
            "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {jwt}",
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

            try:
                conn, jwt = init()  # We are creating a new connection because we are using multiple threads
                df = pd.read_sql(sql_query, conn)

                if df.empty:
                    say("🚨 Query returned no data.")
                else:
                    result_text = df.to_string(index=False)[:3000]
                    say(f"📊 **Query Result:**\n```{result_text}```")

            except Exception as e:
                say(f"⚠️ Error executing query: {e}")


def init():
    """Preparing connection with Snowflake and JWT token.."""
    conn, jwt = None, None
    conn = snowflake.connector.connect(
        user=USER,
        password=PASSWORD,
        account=ACCOUNT
    )
    
    jwt = generate_jwt.JWTGenerator(
        ACCOUNT, USER, RSA_PRIVATE_KEY_PATH, timedelta(minutes=59), timedelta(minutes=54) 
    ).get_token()
    
    return conn, jwt


# Start application
if __name__ == "__main__":
    CONN, JWT = init()
    if not CONN.rest.token:
        print("Error: Failed to connect to Snowflake! Please check your Snowflake user, password, and account environment variables and try again.")
        quit()
    SocketModeHandler(app, SLACK_APP_TOKEN).start()
