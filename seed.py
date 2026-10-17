"""Run once: python seed.py  (resets the database with the fictional simulated election)."""
import secrets
import io, random
from main import (Base, engine, SessionLocal, User, Election, Candidate, Announcement,
                  hash_password, recompute_credibility, PROGRAMS, STUDENT_TOTAL, account_programs, fictional_names)

# Fictional voter names: random first-name + surname combinations, so the Voters list shows names, not "Student 1".
# They are made up for the simulation and do not refer to real students.
# (names, program split and the account count come from main.py so the seed and the startup top-up always agree)


def avatar_jpeg(bg, fg):
    """Flat person-silhouette placeholder photo for the fictional candidates (no real people)."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return None
    img = Image.new("RGB", (480, 480), bg)
    d = ImageDraw.Draw(img)
    d.ellipse((150, 70, 330, 250), fill=fg)          # head
    d.ellipse((60, 270, 420, 640), fill=fg)          # shoulders
    out = io.BytesIO()
    img.save(out, "JPEG", quality=85)
    return out.getvalue()


AVATAR_COLORS = [((114, 9, 39), (235, 200, 210)), ((31, 111, 139), (205, 230, 238)), ((76, 122, 52), (214, 232, 204)),
                 ((106, 76, 147), (225, 214, 238)), ((193, 68, 14), (246, 214, 198))]

import sys
if "--if-empty" in sys.argv:  # used by the hosted start command: seed only the first time, never wipe real votes
    with SessionLocal() as _db:
        if _db.query(User).count() > 0:
            print("Database already has data. Skipping seed.")
            sys.exit(0)
Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)
db = SessionLocal()

# Pre-loaded accounts (the prototype has no student-records integration).
# 500 fictional voter accounts by default (set VOTERA_STUDENT_ACCOUNTS to change): the Table 1 proportions across the eight programs
# plus 14 spare accounts for testers. Student numbers use the PUP format YYYY-NNNNN-CM-N and are
# fictional (the 9xxxx range), not real students.
# Shared password mode (default): everyone uses "student123".
# Unique password mode:  UNIQUE_PASSWORDS=1 python seed.py  -> random password per account, saved to credentials.csv
import os, csv
UNIQUE = os.getenv("UNIQUE_PASSWORDS") == "1"
db.add(User(student_number="ADMIN-001", full_name="Election Administrator", program="SEC",
            password_hash=hash_password("admin123"), role="admin", otp_secret=secrets.token_hex(10)))
programs_for_accounts = account_programs(STUDENT_TOTAL or 500)   # Table 1 split scaled to the total, plus 14 spare testers
shared_hash = hash_password("student123")  # one bcrypt hash reused so seeding stays fast
creds = []
names = fictional_names(len(programs_for_accounts))
for i, prog in enumerate(programs_for_accounts, start=1):
    sn = f"2022-{90000 + i:05d}-CM-0"
    pw = secrets.token_urlsafe(6) if UNIQUE else "student123"
    db.add(User(student_number=sn, full_name=names[i - 1], program=prog, respondent_code=f"R-{i:03d}",
                password_hash=hash_password(pw) if UNIQUE else shared_hash,
                role="student", otp_secret=secrets.token_hex(10)))
    creds.append((sn, names[i - 1], prog, pw))
if UNIQUE:
    with open("credentials.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["student_number", "name", "program", "password"]); w.writerows(creds)
    print("Wrote credentials.csv (keep it private; hand out one row per respondent).")

e = Election(title="Simulated SSC Election 2026-2027", status="open")
db.add(e)
db.flush()

# Fictional candidates. Miguel and Carla are deliberately near-identical so the originality check flags them.
# Last three numbers = administrator-entered scores (achievements, leadership, community), 0-100, fictional.
cands = [
    ("President", "Ana Reyes", "BSIT", "I will make student services faster and easier by bringing enrollment concerns, scholarship updates, and clearance steps into one clear online guide. I will also open a mental health desk with trained peer listeners and partner with the guidance office for regular wellness weeks.",
     "Dean's Lister, three semesters. Hackathon finalist, 2025.", "Class president, 2nd year. Org vice president, 3rd year.", "Led a donation drive for flood-affected families.", (90, 85, 80)),
    ("President", "Miguel Santos", "BSBA - HRM", "I will push for a student council that listens first and acts fast. My platform focuses on free tutoring programs, a transparent budget report every month, and stronger support for student organizations across all programs. Every student deserves a voice, and I will make sure every concern reaches the administration.",
     "Best Thesis Proposal, department level.", "Org treasurer, 3rd year. Class secretary, 2nd year.", "Volunteer in a campus tree-planting activity.", (70, 75, 60)),
    ("Vice President", "Carla Mendoza", "BSBA - MM", "I will push for a student council that listens first and acts quickly. My platform focuses on free tutoring programs, a transparent budget report every month, and stronger support for student organizations across all programs. Every student deserves a voice, and I will make sure each concern reaches the administration.",
     "Marketing case competition participant.", "Class representative, 3rd year.", "Joined a literacy outreach program.", (60, 65, 70)),
    ("Vice President", "Paolo Villanueva", "BS Entrepreneurship", "My focus is campus life outside the classroom. I will organize quarterly sports fests and cultural nights, create a job fair with partner companies for graduating students, and set up a small business bazaar where student entrepreneurs can sell on campus at no cost.",
     "Startup pitch competition, second place.", "Org president, 3rd and 4th year.", "Organized a livelihood training for a nearby community.", (75, 90, 85)),
    ("Secretary-General", "Liza Navarro", "BTLEd - ICT", "I will work with the administration on safer walkways, better lighting, working restrooms, and accessible ramps and elevators for students with mobility needs. I will also press for fair canteen prices and a monthly open forum where students can question the council directly.",
     "Academic excellence award, 2nd year.", "Peer tutor coordinator. Class vice president, 3rd year.", "Regular blood donation drive volunteer.", (85, 80, 90)),
    ("Secretary-General", "Jose Ramos", "BPA - Fiscal Administration",
     "Council records should be easy for any student to read. I will post short minutes within two days of every meeting, keep one public calendar of council activities, and set up a suggestion box that is answered in writing every week.",
     "Best in Public Speaking, 2nd year.", "Org secretary, 3rd year.", "Helped organize a school supplies giveaway.", (65, 70, 65)),
    ("Treasurer", "Maria Cruz", "DOMT - Medical Office Management",
     "Every peso of council funds should have a receipt a student can see. I will publish a simple income and spending sheet each month, ask students to vote on how leftover funds are used, and cut costs on events by asking partner shops for discounts.",
     "Scholar with high honors, 2nd and 3rd year.", "Org auditor, 3rd year.", "Joined a community health outreach.", (80, 70, 75)),
    ("Treasurer", "Noel Bautista", "BTLEd - Home Economics",
     "I want a council that runs on fundraising, not on student fees. My plan is a cooking and baking sale each term, a recycling drive that turns used paper into funds, and a clear signboard that shows what each activity earned and what it cost.",
     "Home economics skills competition, regional participant.", "Class treasurer, 2nd and 3rd year.", "Fed families during a relief operation.", (70, 65, 80)),
]
for k, (position, name, prog, manifesto, ach, lead, comm, (sa, sl, sc)) in enumerate(cands):
    photo = avatar_jpeg(*AVATAR_COLORS[k % len(AVATAR_COLORS)])
    db.add(Candidate(election_id=e.id, full_name=name, program=prog, position=position,
                     manifesto=manifesto, achievements=ach, leadership=lead, community=comm,
                     achievements_score=sa, leadership_score=sl, community_score=sc,
                     photo=photo, photo_type="image/jpeg" if photo else None, photo_version=1 if photo else 0))

db.add(Announcement(election_id=e.id, title="Voting is now open", category="Schedule", pinned=True,
                    body="Log in with your student number, password, and OTP to cast your vote. You vote once for each position: President, Vice President, Secretary-General and Treasurer."))
db.add(Announcement(election_id=e.id, title="Review the candidates first", category="Reminder",
                    body="Open each candidate profile and compare platforms before voting."))
db.add(Announcement(election_id=e.id, title="How voting works", category="Rules",
                    body="One vote per position. Your vote cannot be changed after it is recorded, and you get a transaction ID for each one."))
db.commit()

# Run the credibility checker so every candidate already has similarity, originality, and credibility scores.
for c in recompute_credibility(db, e.id):
    print(f"{c.full_name:18} similarity={c.highest_similarity:.4f} originality={c.originality_score:6.2f} "
          f"flagged={c.flagged} credibility={c.credibility_score}")
print(f"Seeded. Admin: ADMIN-001 / admin123. {len(creds)} students: 2022-90001-CM-0 to 2022-{90000+len(creds)}-CM-0 / " + ("see credentials.csv" if UNIQUE else "student123"))