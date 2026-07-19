"""Profile where the 2-second delay comes from."""
import time

t = time.time()
print(f"0.000: Starting import")

from agents.agent_a import app, AgentRequest, handle_agent_request
print(f"{time.time() - t:.3f}: Imported agent_a")

from fastapi.testclient import TestClient
client = TestClient(app)
print(f"{time.time() - t:.3f}: Created TestClient")

req_body = {"message": "hello", "conversation_history": [], "tool_call": None}

# First request
r1 = client.post("/agent", json=req_body)
print(f"{time.time() - t:.3f}: First request done (status={r1.status_code})")

# Second request
r2 = client.post("/agent", json=req_body)
print(f"{time.time() - t:.3f}: Second request done (status={r2.status_code})")

# Third request
r3 = client.post("/agent", json=req_body)
print(f"{time.time() - t:.3f}: Third request done (status={r3.status_code})")
