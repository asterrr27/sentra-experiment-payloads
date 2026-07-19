import requests
import time

for i in range(5):
    t = time.time()
    r = requests.post("http://localhost:8001/agent", json={"message": f"hello {i}", "conversation_history": [], "tool_call": None}, timeout=10)
    elapsed = time.time() - t
    print(f"Request {i}: {elapsed:.3f}s (status={r.status_code})")
