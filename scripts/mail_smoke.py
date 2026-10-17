"""Live smoke test of the email intake: a tester inbox emails the Sandtrap inbox, Sandtrap scans and replies. (hackathon-built)"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.app.sandtrap.mail import Mailbox, run  # noqa: E402

target = sys.argv[1] if len(sys.argv) > 1 else "fixture:gated-stealer"
scanner = Mailbox()
print("scanner inbox:", scanner.inbox()["email"])
tester = Mailbox(username="sandtrap-tester", state_path="out/mail_state_tester.json")
t_inbox = tester.inbox()
print("tester inbox: ", t_inbox["email"])
sent = tester._call("POST", f"/inboxes/{t_inbox['inbox_id']}/messages/send",
                    json={"to": [scanner.inbox()["email"]], "subject": "please scan this package", "text": f"Hi, is {target} safe to install?"})
print("sent request:", sent.get("message_id"))
time.sleep(6)  # let the message arrive
t0 = time.time()
run(once=True, publish=True)
print(f"scanner handled the mailbox in {time.time()-t0:.0f}s")
time.sleep(6)
listing = tester._call("GET", f"/inboxes/{t_inbox['inbox_id']}/messages", params={"limit": 5})
for m in listing.get("messages", []):
    if "sent" in (m.get("labels") or []):
        continue
    full = tester._call("GET", f"/inboxes/{t_inbox['inbox_id']}/messages/{m['message_id']}")
    print("\n=== reply received by the tester ===\nSubject:", full.get("subject"), "\nFrom:", full.get("from"), "\n")
    print((full.get("text") or full.get("extracted_text") or "")[:1500])
    break
else:
    print("no reply found yet")
