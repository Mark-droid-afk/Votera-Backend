"""Run after seeding:  python test_phase6.py -- audit log, lockout, self-test, candidate link/Q&A, auto column upgrade."""
from fastapi.testclient import TestClient
from main import app

with TestClient(app) as client:
    def login(sn, pw, portal):
        r = client.post("/auth/login", json={"student_number": sn, "password": pw, "portal": portal})
        assert r.status_code == 200, r.text
        r2 = client.post("/auth/verify-otp", json={"otp_token": r.json()["otp_token"], "code": r.json()["dev_otp"]})
        return r2.json(), {"Authorization": "Bearer " + r2.json()["access_token"]}

    _, admin = login("ADMIN-001", "admin123", "admin")
    _, s1 = login("2022-90001-CM-0", "student123", "student")

    # lockout: 5 wrong passwords -> 429, even the right password is refused during the lock
    sn = "2022-90005-CM-0"
    codes = [client.post("/auth/login", json={"student_number": sn, "password": "wrong", "portal": "student"}).status_code for _ in range(5)]
    assert codes == [401, 401, 401, 401, 429], codes
    r = client.post("/auth/login", json={"student_number": sn, "password": "student123", "portal": "student"})
    assert r.status_code == 429 and "minute" in r.json()["detail"], r.text
    print("PASS 5 wrong passwords lock the account (429, even the right password is refused)")
    # other accounts unaffected
    login("2022-90006-CM-0", "student123", "student")
    print("PASS other accounts unaffected")

    # wrong OTP lockout
    sn2 = "2022-90007-CM-0"
    r = client.post("/auth/login", json={"student_number": sn2, "password": "student123", "portal": "student"}).json()
    bad = "000000" if r["dev_otp"] != "000000" else "111111"
    oc = [client.post("/auth/verify-otp", json={"otp_token": r["otp_token"], "code": bad}).status_code for _ in range(5)]
    assert oc == [401, 401, 401, 401, 429], oc
    print("PASS 5 wrong OTP codes lock the account")

    # audit log
    assert client.get("/admin/audit-log", headers=s1).status_code == 403
    log = client.get("/admin/audit-log", headers=admin).json()
    actions = {x["action"] for x in log}
    assert {"login", "login_failed", "otp_failed"} <= actions, actions
    assert all("password" not in x["detail"].lower() or "wrong" in x["detail"].lower() or "accepted" in x["detail"].lower() or "new passwords" in x["detail"].lower() for x in log)
    probs = client.get("/admin/audit-log?only_problems=true", headers=admin).json()
    assert probs and all(not x["ok"] for x in probs)
    assert log[0]["id"] > log[-1]["id"] and log[0]["at"].endswith("Z")
    print("PASS audit log: admin only, newest first, problems filter, no secrets")

    # actions get logged
    client.put("/admin/election/status", headers=admin, json={"status": "open"})
    cid = client.get("/candidates", headers=s1).json()[0]["id"]
    assert client.post("/vote", headers=s1, json={"candidate_id": cid}).status_code == 200
    acts = [x["action"] for x in client.get("/admin/audit-log", headers=admin).json()]
    assert "election_status" in acts and "vote_cast" in acts
    detail = [x for x in client.get("/admin/audit-log", headers=admin).json() if x["action"] == "vote_cast"][0]["detail"]
    assert str(cid) not in detail.replace("Vote recorded (choice not logged here)", "")
    print("PASS status change and vote are logged; the vote choice is not")

    # candidate video + Q&A
    c = client.get("/candidates", headers=admin).json()[0]
    body = {k: c[k] for k in ("full_name", "program", "position", "manifesto", "achievements", "leadership", "community")}
    body.update(video_url="https://example.com/v", qa="Q: Why run?\nA: To help.")
    # edit is blocked? (edit allowed even after votes)
    r = client.put(f"/admin/candidates/{c['id']}", headers=admin, json=body)
    assert r.status_code == 200 and r.json()["video_url"] == "https://example.com/v" and "Why run" in r.json()["qa"], r.text
    assert client.get(f"/candidates/{c['id']}", headers=s1).json()["video_url"] == "https://example.com/v"
    print("PASS candidate video link and Q&A saved and visible to students")

    # self test
    assert client.get("/admin/selftest", headers=s1).status_code == 403
    st = client.get("/admin/selftest", headers=admin).json()
    for x in st["checks"]:
        print(("  ok   " if x["ok"] else "  FAIL ") + x["group"] + ": " + x["name"] + " - " + x["detail"])
    assert st["passed"] == st["total"] == len(st["checks"]) and st["total"] >= 13, st
    print(f"PASS self-test {st['passed']}/{st['total']}")
    client.post("/admin/election/reset", headers=admin)
print("ALL PHASE 6 TESTS PASSED")