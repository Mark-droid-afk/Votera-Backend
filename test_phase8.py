"""Run after seeding:  python test_phase8.py  -- receipt verification, feedback, backup."""
import os
os.environ.setdefault("DATABASE_URL", "sqlite:///./votera.db")
from fastapi.testclient import TestClient
import main

with TestClient(main.app) as client:
    def login(sn, pw, role):
        r = client.post("/auth/login", json={"student_number": sn, "password": pw, "role": role}).json()
        v = client.post("/auth/verify-otp", json={"otp_token": r["otp_token"], "code": r["dev_otp"]}).json()
        return {"Authorization": "Bearer " + v["access_token"]}
    admin = login("ADMIN-001", "admin123", "admin")
    s = login("2022-90001-CM-0", "student123", "student")
    s2 = login("2022-90002-CM-0", "student123", "student")
    client.post("/admin/election/reset", headers=admin)
    client.put("/admin/election/status", headers=admin, json={"status": "open"})
    cands = client.get("/candidates", headers=s).json()
    by = {c["full_name"]: c["id"] for c in cands}
    tx = client.post("/vote", headers=s, json={"candidate_id": by["Ana Reyes"]}).json()["transaction_id"]

    v = client.get("/vote/verify", params={"tx": tx}, headers=s).json()
    assert v["valid"] and v["yours"] and v["position"] == "President" and v["candidate_name"] == "Ana Reyes"
    v2 = client.get("/vote/verify", params={"tx": tx.upper()}, headers=s2).json()
    assert v2["valid"] and not v2["yours"] and "candidate_name" not in v2
    assert client.get("/vote/verify", params={"tx": "0" * 64}, headers=s).json()["valid"] is False
    assert client.get("/vote/verify", params={"tx": "abc"}, headers=s).json()["valid"] is False
    print("PASS verify receipt: owner sees the choice, others only see that it exists, bad IDs rejected")

    assert client.get("/feedback/mine", headers=s).json()["submitted"] is False
    assert client.post("/feedback", headers=s, json={"ease": 6, "clarity": 4, "trust": 4, "overall": 4}).status_code == 422
    assert client.post("/feedback", headers=s, json={"ease": 5, "clarity": 4, "trust": 4, "overall": 5, "comment": "Clear   and fast"}).status_code == 200
    assert client.post("/feedback", headers=s, json={"ease": 3, "clarity": 4, "trust": 4, "overall": 5, "comment": "Clear and fast"}).status_code == 200
    assert client.post("/feedback", headers=s2, json={"ease": 5, "clarity": 5, "trust": 5, "overall": 5}).status_code == 200
    me = client.get("/feedback/mine", headers=s).json()
    assert me["submitted"] and me["ease"] == 3 and me["comment"] == "Clear and fast"
    fb = client.get("/admin/feedback", headers=admin).json()
    assert fb["count"] == 2 and fb["ease"] == 4.0 and len(fb["comments"]) == 1 and "student_number" not in fb["comments"][0]
    assert client.get("/admin/feedback", headers=s).status_code == 403
    assert client.post("/feedback", headers=admin, json={"ease": 5, "clarity": 5, "trust": 5, "overall": 5}).status_code == 403
    print("PASS feedback: validation, one rating per student (latest wins), anonymous comments, students cannot read the summary")

    b = client.get("/admin/backup", headers=admin).json()
    assert b["election"]["status"] == "open" and len(b["candidates"]) == 8 and len(b["votes"]) == 1 and b["feedback"]["count"] == 2
    assert "password" not in str(b).lower()
    assert client.get("/admin/backup", headers=s).status_code == 403
    print("PASS backup export: candidates, votes, turnout, feedback; admin only; no passwords")
    client.post("/admin/election/reset", headers=admin)
print("ALL PHASE 8 CHECKS PASSED")