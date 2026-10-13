"""Run after seeding:  python test_phase3.py  -- live sync, vote audit, candidate management, formats."""
from fastapi.testclient import TestClient
from main import app

with TestClient(app) as client:  # context manager runs startup (captures the event loop for WebSocket broadcast)
    def login(sn, pw, portal):
        r = client.post("/auth/login", json={"student_number": sn, "password": pw, "portal": portal})
        assert r.status_code == 200, r.text
        r2 = client.post("/auth/verify-otp", json={"otp_token": r.json()["otp_token"], "code": r.json()["dev_otp"]})
        return r2.json()["access_token"], {"Authorization": "Bearer " + r2.json()["access_token"]}

    assert client.get("/health").json()["status"] == "ok"
    # format validation (student portal only)
    for bad in ("2026-0001", "2022-90001-CM", "2022-9001-CM-0", "abcd-90001-CM-0"):
        r = client.post("/auth/login", json={"student_number": bad, "password": "x", "portal": "student"})
        assert r.status_code == 422 and "YYYY-NNNNN-CM-N" in r.json()["detail"], (bad, r.text)
    print("PASS bad student-number formats rejected with an example message")
    # lowercase / spaces tolerated
    assert client.post("/auth/login", json={"student_number": " 2022-90001-cm-0 ", "password": "student123", "portal": "student"}).status_code == 200
    print("PASS format is case/space tolerant")

    atok, admin = login("ADMIN-001", "admin123", "admin")
    s1tok, s1 = login("2022-90001-CM-0", "student123", "student")
    s2tok, s2 = login("2022-90002-CM-0", "student123", "student")
    client.put("/admin/election/status", headers=admin, json={"status": "open"})

    # websocket: bad token closed, good token receives broadcast on another user's vote
    try:
        with client.websocket_connect("/ws") as ws:
            ws.send_json({"token": "garbage"}); ws.receive_json()
        raise AssertionError("bad token should be refused")
    except Exception as e:
        assert "AssertionError" not in type(e).__name__
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"token": s2tok})
        assert ws.receive_json()["type"] == "ready"
        cands = client.get("/candidates", headers=s1).json()
        assert "most_similar_name" not in cands[0]  # students do not see this
        r = client.post("/vote", headers=s1, json={"candidate_id": cands[0]["id"]})
        assert r.status_code == 200, r.text
        msg = ws.receive_json()
        assert msg["type"] == "changed" and "results" in msg["topics"]
    print("PASS websocket: bad token refused; another student's vote pushes a 'results' change")

    # students cannot see audit, voters, export, turnout; only totals via /results
    for path in ("/admin/votes", "/admin/voters", "/admin/turnout", "/admin/export/votes.csv"):
        assert client.get(path, headers=s1).status_code == 403, path
    res = client.get("/results", headers=s1).json()
    assert "student_number" not in str(res) and res["results"][0]["votes"] == 1
    print("PASS students get 403 on every admin audit endpoint; /results has totals only")

    # admin audit
    a = client.get("/admin/votes", headers=admin).json()
    assert len(a) == 1 and a[0]["student_number"] == "2022-90001-CM-0" and a[0]["candidate_name"] == cands[0]["full_name"]
    voters = client.get("/admin/voters", headers=admin).json()
    assert len(voters) == 250 and sum(v["has_voted"] for v in voters) == 1
    t = client.get("/admin/turnout", headers=admin).json()
    assert len(t) == 8 and sum(x["voted"] for x in t) == 1 and sum(x["eligible"] for x in t) == 250
    csvt = client.get("/admin/export/votes.csv", headers=admin)
    assert csvt.text.splitlines()[0].startswith("student_number") and "2022-90001-CM-0" in csvt.text
    print("PASS admin sees who voted for whom, 250 voters, turnout per program (8), CSV export")

    # admin sees "most similar to"
    ac = client.get("/candidates", headers=admin).json()
    miguel = next(c for c in ac if c["full_name"] == "Miguel Santos")
    assert miguel["most_similar_name"] == "Carla Mendoza"
    print("PASS admin sees most_similar_name (Miguel -> Carla)")

    # candidate changes blocked once votes exist; reset clears; then add/edit/delete work
    body = {"full_name": "Test Candidate", "program": "BSIT", "manifesto": "I will plant trees and build a rooftop garden."}
    assert client.post("/admin/candidates", headers=admin, json=body).status_code == 409
    assert client.delete(f"/admin/candidates/{cands[0]['id']}", headers=admin).status_code == 409
    r = client.post("/admin/election/reset", headers=admin).json()
    assert r["votes_removed"] == 1 and r["status"] == "upcoming"
    assert client.get("/admin/votes", headers=admin).json() == []
    assert client.get("/vote/status", headers=s1).json()["has_voted"] is False
    new = client.post("/admin/candidates", headers=admin, json=body)
    assert new.status_code == 200 and new.json()["originality_score"] is not None
    nid = new.json()["id"]
    # copy Ana's manifesto -> flagged, similar to Ana
    ana = next(c for c in ac if c["full_name"] == "Ana Reyes")
    r = client.put(f"/admin/candidates/{nid}", headers=admin, json={**body, "manifesto": ana["manifesto"]}).json()
    assert r["flagged"] and r["most_similar_name"] == "Ana Reyes", r
    assert client.post("/admin/candidates", headers=s1, json=body).status_code == 403
    assert client.delete(f"/admin/candidates/{nid}", headers=admin).status_code == 200
    ac2 = client.get("/candidates", headers=admin).json()
    assert len(ac2) == 5 and not next(c for c in ac2 if c["full_name"] == "Ana Reyes")["flagged"]
    print("PASS add/edit/delete candidate recomputes TF-IDF for the whole field; copy flagged; reset clears votes; students 403")
    client.put("/admin/election/status", headers=admin, json={"status": "open"})
    # demo fill + survey_url key present
    assert "survey_url" in client.get("/election", headers=s1).json()
    assert client.post("/admin/demo/fill", headers=s1, json={"count": 5}).status_code == 403
    assert client.post("/admin/demo/fill", headers=admin, json={"count": 25}).json()["added"] == 25
    assert client.get("/results", headers=s1).json()["turnout"]["votes_cast"] == 25
    assert client.post("/admin/demo/fill", headers=admin, json={"count": 5}).json()["added"] == 5
    client.post("/admin/election/reset", headers=admin)
    client.put("/admin/election/status", headers=admin, json={"status": "open"})
    print("PASS demo fill casts 25 then 5 more distinct votes; students 403; survey_url exposed")
print("ALL PHASE 3 CHECKS PASSED")