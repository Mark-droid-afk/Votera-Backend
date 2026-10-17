"""Run after seeding:  python test_phase9.py  -- sample candidates for every position are added once, automatically."""
import os
os.environ.setdefault("DATABASE_URL", "sqlite:///./votera.db")
os.environ["VOTERA_AUTO_SAMPLES"] = "1"
from fastapi.testclient import TestClient
import main

def login(client, sn, pw, role):
    r = client.post("/auth/login", json={"student_number": sn, "password": pw, "role": role}).json()
    v = client.post("/auth/verify-otp", json={"otp_token": r["otp_token"], "code": r["dev_otp"]}).json()
    return {"Authorization": "Bearer " + v["access_token"]}

with TestClient(main.app) as client:            # startup adds the samples
    admin = login(client, "ADMIN-001", "admin123", "admin")
    cs = client.get("/candidates", headers=admin).json()
    assert len(cs) == 24 and len({c["position"] for c in cs}) == 12, len(cs)
    for pos in ("President", "Vice President", "Secretary-General", "Treasurer", "Auditor", "Logistics and Technical Councilor (LTC)"):
        assert sum(c["position"] == pos for c in cs) == 2, pos
    print("PASS startup adds 24 sample candidates, two for each of the 12 positions")
    gone = cs[-1]["id"]
    assert client.delete(f"/admin/candidates/{gone}", headers=admin).status_code == 200

with TestClient(main.app) as client:            # a second start must not add it back
    admin = login(client, "ADMIN-001", "admin123", "admin")
    assert len(client.get("/candidates", headers=admin).json()) == 23
    client.post("/admin/election/reset", headers=admin)
    assert len(client.get("/candidates", headers=admin).json()) == 23
    print("PASS done once only: a removed sample candidate stays removed after restart and reset")
print("ALL PHASE 9 CHECKS PASSED")