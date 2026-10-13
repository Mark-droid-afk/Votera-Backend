"""Run after seeding:  python test_phase4.py  -- voter upload, candidate photos, real names."""
import io
from fastapi.testclient import TestClient
from main import app

with TestClient(app) as client:
    def login(sn, pw, portal):
        r = client.post("/auth/login", json={"student_number": sn, "password": pw, "portal": portal})
        assert r.status_code == 200, r.text
        r2 = client.post("/auth/verify-otp", json={"otp_token": r.json()["otp_token"], "code": r.json()["dev_otp"]})
        return {"Authorization": "Bearer " + r2.json()["access_token"]}

    admin = login("ADMIN-001", "admin123", "admin")
    s1 = login("2022-90001-CM-0", "student123", "student")

    voters = client.get("/admin/voters", headers=admin).json()
    assert len(voters) == 250 and not any("Sample" in v["full_name"] for v in voters)
    assert len({v["full_name"] for v in voters}) == 250
    print("PASS 250 voters have real-looking unique names (no 'Sample Student')")

    # format guide
    f = client.get("/admin/voters/format", headers=admin).json()
    assert f["columns"] == "student_number,full_name,program,password" and len(f["programs"]) == 8
    assert client.get("/admin/voters/format", headers=s1).status_code == 403
    print("PASS format guide available to admin only")

    good = ("student_number,full_name,program,password\n"
            "2022-90251-CM-0,Juan Dela Cruz,BSIT,\n"
            "2022-90252-CM-0,Maria Santos,bsba - hrm,mypass123\n"
            "2022-90001-CM-0,Duplicate Person,BSIT,\n"          # already exists
            "2022-9253-CM-0,Bad Number,BSIT,\n"                  # bad format
            "2022-90254-CM-0,Bad Program,BSN,\n"                 # unknown program
            "2022-90255-CM-0,Short Pass,BSIT,abc\n"              # short password
            "2022-90252-CM-0,Twice,BSIT,\n")                     # duplicate within file
    r = client.post("/admin/voters/import", headers=admin, json={"csv": "﻿" + good})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["created"] == 2 and j["skipped"] == 5, j
    assert len(j["generated"]) == 1 and j["generated"][0]["student_number"] == "2022-90251-CM-0" and len(j["generated"][0]["password"]) >= 6
    reasons = " | ".join(e["reason"] for e in j["errors"])
    for part in ("2020-00000-CM-0", "unknown program", "at least 6", "already has an account", "listed twice"):
        assert part in reasons, (part, reasons)
    print("PASS import: 2 created, 5 skipped with reasons, 1 password generated")

    # new accounts can log in (generated and chosen password); counts updated
    login("2022-90251-CM-0", j["generated"][0]["password"], "student")
    login("2022-90252-CM-0", "mypass123", "student")
    assert client.get("/results", headers=s1).json()["turnout"]["eligible_voters"] == 252
    print("PASS imported students can log in; eligible voters = 252")

    # semicolon file, missing column, empty, too many rows, RBAC
    semi = "Student Number;Name;Course\n2022-90260-CM-0;Pedro Reyes;BSIT\n"
    assert client.post("/admin/voters/import", headers=admin, json={"csv": semi}).json()["created"] == 1
    miss = client.post("/admin/voters/import", headers=admin, json={"csv": "student_number,full_name\n2022-90261-CM-0,X\n"})
    assert miss.status_code == 422 and "program" in miss.json()["detail"]
    assert client.post("/admin/voters/import", headers=admin, json={"csv": ""}).status_code == 422
    big = "student_number,full_name,program\n" + "".join(f"2022-{91000+i:05d}-CM-0,N{i},BSIT\n" for i in range(201))
    assert client.post("/admin/voters/import", headers=admin, json={"csv": big}).status_code == 422
    assert client.post("/admin/voters/import", headers=s1, json={"csv": good}).status_code == 403
    print("PASS semicolon + alias headers accepted; missing column, empty, >200 rows rejected; students 403")

    # photos
    cands = client.get("/candidates", headers=s1).json()
    assert all(c["photo_version"] >= 1 for c in cands)
    p = client.get(f"/candidates/{cands[0]['id']}/photo", headers=s1)
    assert p.status_code == 200 and p.content[:3] == b"\xff\xd8\xff"
    from PIL import Image
    buf = io.BytesIO(); Image.new("RGB", (50, 50), (10, 20, 30)).save(buf, "PNG")
    cid = cands[1]["id"]
    up = client.put(f"/admin/candidates/{cid}/photo", headers=admin, content=buf.getvalue())
    assert up.status_code == 200 and up.json()["photo_version"] == cands[1]["photo_version"] + 1
    assert client.get(f"/candidates/{cid}/photo", headers=s1).headers["content-type"] == "image/png"
    assert client.put(f"/admin/candidates/{cid}/photo", headers=admin, content=b"not an image").status_code == 415
    assert client.put(f"/admin/candidates/{cid}/photo", headers=admin, content=b"\xff\xd8\xff" + b"0" * 2_100_000).status_code == 413
    assert client.put(f"/admin/candidates/{cid}/photo", headers=s1, content=buf.getvalue()).status_code == 403
    assert client.delete(f"/admin/candidates/{cid}/photo", headers=admin).json()["photo_version"] > up.json()["photo_version"]
    assert client.get(f"/candidates/{cid}/photo", headers=s1).status_code == 404
    print("PASS photos: seeded, served to students, admin upload/replace/delete, type + size checks, students 403")
print("ALL PHASE 4 CHECKS PASSED")