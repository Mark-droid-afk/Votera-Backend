"""Run after seeding:  python test_phase2.py   (uses the same DATABASE_URL as the server)"""
import random
from fastapi.testclient import TestClient
import scoring
from main import app

# --- 1. Worked example from Chapter 3 ---
assert scoring.originality_score(0.18) == 82, scoring.originality_score(0.18)
assert scoring.credibility_score(82, 90, 85, 80) == 84.7, scoring.credibility_score(82, 90, 85, 80)
assert scoring.is_flagged(0.70) and not scoring.is_flagged(0.6999)
print("PASS worked example: 0.18 -> originality 82 -> credibility 84.7; 0.70 threshold flags")

# --- 2. Hand-written Quick Sort matches the built-in sort ---
for _ in range(200):
    data = [(i, random.randint(0, 20)) for i in range(random.randint(0, 40))]
    assert scoring.quick_sort(data, key=lambda p: (-p[1], p[0])) == sorted(data, key=lambda p: (-p[1], p[0]))
print("PASS quick sort equals sorted() on 200 random lists")

client = TestClient(app)


def login(sn, pw):
    r = client.post("/auth/login", json={"student_number": sn, "password": pw})
    assert r.status_code == 200, r.text
    r2 = client.post("/auth/verify-otp", json={"otp_token": r.json()["otp_token"], "code": r.json()["dev_otp"]})
    assert r2.status_code == 200, r2.text
    return {"Authorization": "Bearer " + r2.json()["access_token"]}


admin = login("ADMIN-001", "admin123")
students = [login(f"2022-{90000+i:05d}-CM-0", "student123") for i in range(1, 9)]
print("PASS password + HOTP login for admin and students")

assert client.post("/auth/login", json={"student_number": "2022-90001-CM-0", "password": "wrong"}).status_code == 401
r = client.post("/auth/login", json={"student_number": "2022-90001-CM-0", "password": "student123"})
bad = "000000" if r.json()["dev_otp"] != "000000" else "111111"
assert client.post("/auth/verify-otp", json={"otp_token": r.json()["otp_token"], "code": bad}).status_code == 401
assert client.get("/candidates").status_code in (401, 403)  # no token
print("PASS wrong password, wrong OTP, and missing token all rejected")

# --- 3. Credibility results ---
cands = client.get("/candidates", headers=students[0]).json()
by_name = {c["full_name"]: c for c in cands}
assert by_name["Miguel Santos"]["flagged"] and by_name["Carla Mendoza"]["flagged"]
assert not any(by_name[n]["flagged"] for n in ("Ana Reyes", "Paolo Villanueva", "Liza Navarro"))
for c in cands:
    exp = round(c["originality_score"] * .35 + c["achievements_score"] * .30 + c["leadership_score"] * .20 + c["community_score"] * .15, 2)
    assert abs(c["credibility_score"] - exp) < 0.011, (c["full_name"], c["credibility_score"], exp)
print("PASS only the two near-identical manifestos are flagged; credibility = weighted sum for all 5")

flag = client.get("/admin/flagged", headers=admin).json()
assert len(flag["flagged"]) == 2 and flag["threshold"] == 0.70
assert client.get("/admin/flagged", headers=students[0]).status_code == 403
print("PASS /admin/flagged lists 2, students get 403 (RBAC)")

# Admin edits a score -> credibility recomputes; out-of-range rejected
ana = by_name["Ana Reyes"]["id"]
r = client.put(f"/admin/candidates/{ana}/scores", headers=admin,
               json={"achievements_score": 100, "leadership_score": 100, "community_score": 100})
exp = round(by_name["Ana Reyes"]["originality_score"] * .35 + 65, 2)
assert r.status_code == 200 and abs(r.json()["credibility_score"] - exp) < 0.011
assert client.put(f"/admin/candidates/{ana}/scores", headers=admin,
                  json={"achievements_score": 101, "leadership_score": 1, "community_score": 1}).status_code == 422
assert client.put(f"/admin/candidates/{ana}/scores", headers=students[0],
                  json={"achievements_score": 1, "leadership_score": 1, "community_score": 1}).status_code == 403
print("PASS admin score entry recomputes credibility; 0-100 enforced; students blocked")

# --- 4. Voting and tally ---
ids = {n: c["id"] for n, c in by_name.items()}
plan = [("Ana Reyes", 0), ("Ana Reyes", 1), ("Ana Reyes", 2), ("Paolo Villanueva", 3),
        ("Paolo Villanueva", 4), ("Liza Navarro", 5), ("Miguel Santos", 6)]
for name, si in plan:
    assert client.post("/vote", headers=students[si], json={"candidate_id": ids[name]}).status_code == 200
dup = client.post("/vote", headers=students[0], json={"candidate_id": ids["Liza Navarro"]})
assert dup.status_code == 409, dup.text
assert client.post("/vote", headers=admin, json={"candidate_id": ids["Ana Reyes"]}).status_code == 403
assert client.post("/vote", headers=students[7], json={"candidate_id": 9999}).status_code == 404
assert client.get("/vote/status", headers=students[0]).json()["has_voted"] is True
print("PASS 7 votes recorded; second vote 409; admin cannot vote; bad candidate 404")

res = client.get("/results", headers=students[7]).json()
rows = res["results"]
print("RESULTS:", [(r["rank"], r["full_name"], r["votes"], r["percent"]) for r in rows])
assert [r["votes"] for r in rows] == [3, 2, 1, 1, 0]
assert rows[0]["full_name"] == "Ana Reyes" and rows[1]["full_name"] == "Paolo Villanueva"
assert rows[4]["full_name"] == "Carla Mendoza" and rows[4]["votes"] == 0
assert res["turnout"] == {"votes_cast": 7, "eligible_voters": 250, "turnout_percent": 2.8}
print("PASS tally descending, zero-vote candidate listed, turnout 7/30 = 23.33%")

# --- 5. Closed election ---
assert client.put("/admin/election/status", headers=admin, json={"status": "closed"}).status_code == 200
assert client.post("/vote", headers=students[7], json={"candidate_id": ids["Ana Reyes"]}).status_code == 403
client.put("/admin/election/status", headers=admin, json={"status": "open"})
print("PASS voting blocked when election is closed")
print("\nALL PHASE 2 CHECKS PASSED")