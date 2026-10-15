"""Votera backend - Phase 1 + Phase 2 (prototype).
Chapter 3 mapping: bcrypt password hashing, JWT sessions, RBAC (Admin/Student),
HOTP second factor (delivery simulated), SHA-256 transaction IDs, one-student-one-vote,
TF-IDF + Cosine Similarity originality check, Weighted Sum Model credibility score,
hash map vote tally with Quick Sort.
"""
import os, re, io, csv, time, asyncio, hmac, hashlib, struct, secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import Response
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import (create_engine, select, func, String, Integer, Boolean, Float, Text, LargeBinary,
                        DateTime, ForeignKey, UniqueConstraint)
from sqlalchemy import text as sql_text, inspect as sa_inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

import scoring

SECRET_KEY = os.getenv("VOTERA_SECRET_KEY", "dev-secret-change-me-use-a-long-random-value")
TX_SALT = os.getenv("VOTERA_TX_SALT", "dev-tx-salt-change-me")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./votera.db")
if DATABASE_URL.startswith("postgres://"):  # some hosts hand out the short form; SQLAlchemy wants postgresql://
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]
if DATABASE_URL.startswith("postgresql://"):  # newer SQLAlchemy defaults to the psycopg3 driver; this project installs psycopg2
    DATABASE_URL = "postgresql+psycopg2://" + DATABASE_URL[len("postgresql://"):]

engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False)


class Base(DeclarativeBase):
    pass


def utcnow():
    return datetime.now(timezone.utc)


# ---------------- Data layer ----------------
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    student_number: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120), default="")
    program: Mapped[str] = mapped_column(String(100), default="")
    password_hash: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(10), default="student")  # "admin" or "student"
    otp_secret: Mapped[str] = mapped_column(String(32))
    otp_counter: Mapped[int] = mapped_column(Integer, default=0)
    otp_pending: Mapped[bool] = mapped_column(Boolean, default=False)
    respondent_code: Mapped[str | None] = mapped_column(String(12), nullable=True)  # e.g. R-017, for matching the two surveys without names


class Election(Base):
    __tablename__ = "elections"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(10), default="upcoming")  # upcoming/open/closed
    closes_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # optional automatic closing time (UTC)


class Candidate(Base):
    __tablename__ = "candidates"
    id: Mapped[int] = mapped_column(primary_key=True)
    election_id: Mapped[int] = mapped_column(ForeignKey("elections.id"))
    full_name: Mapped[str] = mapped_column(String(120))
    program: Mapped[str] = mapped_column(String(100), default="")
    position: Mapped[str] = mapped_column(String(80), default="")
    manifesto: Mapped[str] = mapped_column(Text, default="")
    achievements: Mapped[str] = mapped_column(Text, default="")
    leadership: Mapped[str] = mapped_column(Text, default="")
    community: Mapped[str] = mapped_column(Text, default="")
    # Credibility checker output
    highest_similarity: Mapped[float | None] = mapped_column(Float, nullable=True)
    originality_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    photo: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)  # candidate photo (JPEG/PNG)
    photo_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    photo_version: Mapped[int] = mapped_column(Integer, default=0)  # bumps on each upload so phones refresh their cached copy
    most_similar_name: Mapped[str | None] = mapped_column(String(120), nullable=True)  # explainability for the admin
    video_url: Mapped[str | None] = mapped_column(String(300), nullable=True)  # optional link to a platform video
    qa: Mapped[str | None] = mapped_column(Text, nullable=True)  # optional questions and answers, plain text
    # Administrator-entered criterion scores (0-100)
    achievements_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    leadership_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    community_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    credibility_score: Mapped[float | None] = mapped_column(Float, nullable=True)


class Vote(Base):
    __tablename__ = "votes"
    __table_args__ = (UniqueConstraint("election_id", "student_number", name="one_student_one_vote"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    election_id: Mapped[int] = mapped_column(ForeignKey("elections.id"))
    candidate_id: Mapped[int] = mapped_column(ForeignKey("candidates.id"))
    student_number: Mapped[str] = mapped_column(String(32))
    transaction_id: Mapped[str] = mapped_column(String(64), unique=True)
    cast_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Announcement(Base):
    __tablename__ = "announcements"
    id: Mapped[int] = mapped_column(primary_key=True)
    election_id: Mapped[int] = mapped_column(ForeignKey("elections.id"))
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    """Read-only trail of important actions (who, what, when). Never stores passwords, OTP codes or vote choices."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(40), default="")
    role: Mapped[str] = mapped_column(String(10), default="")
    action: Mapped[str] = mapped_column(String(40), default="")
    detail: Mapped[str] = mapped_column(String(300), default="")
    ok: Mapped[bool] = mapped_column(Boolean, default=True)


Base.metadata.create_all(engine)


def ensure_columns():
    """Tiny automatic upgrade: adds columns introduced by newer versions to an existing database,
    so replacing main.py does not force a re-seed (and does not lose votes)."""
    insp = sa_inspect(engine)
    for table in Base.metadata.sorted_tables:
        if not insp.has_table(table.name):
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name not in have:
                ddl = col.type.compile(engine.dialect)
                with engine.begin() as conn:
                    conn.execute(sql_text(f'ALTER TABLE {table.name} ADD COLUMN {col.name} {ddl}'))


ensure_columns()


# ---------------- Security helpers ----------------
PROGRAMS = ["BSIT", "BTLEd - Home Economics", "BTLEd - ICT", "BSBA - HRM", "BSBA - MM",
            "BS Entrepreneurship", "BPA - Fiscal Administration", "DOMT - Medical Office Management"]


def hash_password(pw: str, rounds: int = 12) -> str:
    """Salted, adaptive hashing (bcrypt) - passwords are never stored in plaintext."""
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds)).decode()


def verify_password(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())


def hotp(secret: str, counter: int, digits: int = 6) -> str:
    """HMAC-based One-Time Password (RFC 4226)."""
    h = hmac.new(secret.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def make_token(user: User, scope: str, minutes: int) -> str:
    payload = {"sub": str(user.id), "scope": scope, "role": user.role,
               "exp": utcnow() + timedelta(minutes=minutes)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def transaction_id(student_number: str, election_id: int) -> str:
    """SHA-256 transaction ID tied to the student number. Deterministic per student and
    election, so a second vote by the same student produces the same ID and is rejected."""
    return hashlib.sha256(f"{TX_SALT}|{student_number}|{election_id}".encode()).hexdigest()


# ---------------- Credibility checker (uses scoring.py) ----------------
def recompute_credibility(db: Session, election_id: int) -> list["Candidate"]:
    """Stage 1: TF-IDF + Cosine Similarity against the other candidates' manifestos -> Originality Score
    and review flag. Stage 2: Weighted Sum Model, once the administrator has entered all three scores."""
    cands = db.scalars(select(Candidate).where(Candidate.election_id == election_id).order_by(Candidate.id)).all()
    sims = scoring.compute_similarities_detailed([c.manifesto for c in cands])
    for c, (s, j) in zip(cands, sims):
        c.most_similar_name = cands[j].full_name if j is not None else None
        c.highest_similarity = round(s, 4)
        c.originality_score = scoring.originality_score(s)
        c.flagged = scoring.is_flagged(s)
        if None not in (c.achievements_score, c.leadership_score, c.community_score):
            c.credibility_score = scoring.credibility_score(
                c.originality_score, c.achievements_score, c.leadership_score, c.community_score)
        else:
            c.credibility_score = None
    db.commit()
    return cands


# ---------------- Audit trail and login lockout ----------------
def audit(db: Session, actor: str, role: str, action: str, detail: str = "", ok: bool = True):
    try:
        db.add(AuditLog(actor=actor[:40], role=role[:10], action=action[:40], detail=detail[:300], ok=ok))
        db.commit()
    except Exception:
        db.rollback()


MAX_FAILS = 5          # wrong passwords or OTP codes allowed in a row
LOCK_SECONDS = 300     # then the account waits 5 minutes
_fails: dict[str, list] = {}   # key -> [count, locked_until_epoch]; in memory (prototype), cleared on restart


def lock_remaining(key: str) -> int:
    f = _fails.get(key)
    if f and f[1] > time.time():
        return int(f[1] - time.time()) + 1
    return 0


def register_fail(key: str) -> bool:
    """Counts a failed attempt. Returns True when this attempt locks the account."""
    f = _fails.setdefault(key, [0, 0.0])
    if f[1] and f[1] <= time.time():
        f[0], f[1] = 0, 0.0
    f[0] += 1
    if f[0] >= MAX_FAILS:
        f[0], f[1] = 0, time.time() + LOCK_SECONDS
        return True
    return False


def clear_fails(key: str):
    _fails.pop(key, None)


def lock_message(secs: int) -> str:
    m = (secs + 59) // 60
    return f"Too many wrong attempts. Try again in {m} minute{'s' if m != 1 else ''}."


# ---------------- Dependencies ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


bearer = HTTPBearer()


def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)) -> User:
    try:
        p = jwt.decode(cred.credentials, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    if p.get("scope") != "access":
        raise HTTPException(401, "Invalid token scope")
    user = db.get(User, int(p["sub"]))
    if not user:
        raise HTTPException(401, "User not found")
    return user


def require_role(role: str):
    """Role-Based Access Control."""
    def dep(user: User = Depends(current_user)) -> User:
        if user.role != role:
            raise HTTPException(403, "Not allowed for your role")
        return user
    return dep


SURVEY_URL = os.getenv("VOTERA_SURVEY_URL") or None  # optional link to the post-pilot survey (Parts V-VI)


def now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def election_out(e: "Election") -> dict:
    secs = max(0, int((e.closes_at - now_naive()).total_seconds())) if e.closes_at else None
    return {"id": e.id, "title": e.title, "status": e.status, "survey_url": SURVEY_URL,
            "closes_at": (e.closes_at.isoformat() + "Z") if e.closes_at else None, "seconds_left": secs}


def maybe_autoclose(db: Session, e: "Election") -> bool:
    """If an automatic closing time was set and has passed, close the election (and tell every device)."""
    if e.status == "open" and e.closes_at and now_naive() >= e.closes_at:
        e.status = "closed"
        db.commit()
        notify("election", "results")
        return True
    return False


def next_respondent_code(db: Session) -> int:
    nums = [int(c[2:]) for c in db.scalars(select(User.respondent_code).where(User.respondent_code.is_not(None)))
            if c[2:].isdigit()]
    return (max(nums) if nums else 0) + 1


def get_election(db: Session) -> Election:
    # The prototype runs one pre-configured simulated SSC election.
    e = db.scalar(select(Election).order_by(Election.id))
    if not e:
        raise HTTPException(404, "No election configured. Run seed.py first.")
    maybe_autoclose(db, e)
    return e


# ---------------- Live sync (WebSocket) ----------------
STUDENT_NUMBER_RE = re.compile(r"^\d{4}-\d{5}-CM-\d$")  # e.g. 2020-00000-CM-0


class ConnectionManager:
    """Keeps the open WebSocket connections and tells every device that something changed.
    Messages carry only a topic name ("results", "election", ...). Devices then re-fetch through the
    normal REST endpoints, so role checks (students see totals only) still apply to the data itself."""
    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def broadcast(self, topics: list[str]):
        for ws in list(self.clients):
            try:
                await ws.send_json({"type": "changed", "topics": topics})
            except Exception:
                self.clients.discard(ws)


manager = ConnectionManager()


def notify(*topics: str):
    """Called from the (threaded) REST endpoints after a change is committed."""
    if manager.loop is not None and manager.clients:
        asyncio.run_coroutine_threadsafe(manager.broadcast(list(topics)), manager.loop)


# ---------------- Schemas ----------------
class LoginIn(BaseModel):
    student_number: str
    password: str
    portal: str | None = None  # "student" or "admin": which login screen the app used (RBAC)


class OtpIn(BaseModel):
    otp_token: str
    code: str


class VoteIn(BaseModel):
    candidate_id: int


class StatusIn(BaseModel):
    status: str


class AnnouncementIn(BaseModel):
    title: str
    body: str = ""


class CandidateIn(BaseModel):
    full_name: str = Field(min_length=1, max_length=120)
    program: str = ""
    position: str = "SSC President"
    manifesto: str = ""
    achievements: str = ""
    leadership: str = ""
    community: str = ""
    achievements_score: float | None = Field(default=None, ge=0, le=100)
    leadership_score: float | None = Field(default=None, ge=0, le=100)
    community_score: float | None = Field(default=None, ge=0, le=100)
    video_url: str | None = Field(default=None, max_length=300)
    qa: str | None = Field(default=None, max_length=4000)


class ScoresIn(BaseModel):
    achievements_score: float = Field(ge=0, le=100)
    leadership_score: float = Field(ge=0, le=100)
    community_score: float = Field(ge=0, le=100)


def candidate_out(c: Candidate, admin: bool = False) -> dict:
    d = _candidate_base(c)
    if admin:  # which manifesto it resembles is shown to administrators only
        d["most_similar_name"] = c.most_similar_name
    return d


def _candidate_base(c: Candidate) -> dict:
    return {"id": c.id, "full_name": c.full_name, "program": c.program, "position": c.position,
            "manifesto": c.manifesto, "achievements": c.achievements, "leadership": c.leadership,
            "community": c.community, "highest_similarity": c.highest_similarity,
            "originality_score": c.originality_score, "flagged": c.flagged,
            "achievements_score": c.achievements_score, "leadership_score": c.leadership_score,
            "community_score": c.community_score, "credibility_score": c.credibility_score,
            "photo_version": c.photo_version or 0, "video_url": c.video_url, "qa": c.qa}


# ---------------- Application layer ----------------
app = FastAPI(title="Votera API (prototype)")
app.add_middleware(GZipMiddleware, minimum_size=600)  # smaller responses over mobile data (candidate texts, voter lists)


@app.post("/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    """Step 1: password check, then issue an HOTP. OTP delivery is simulated, so the code is
    returned in the response as dev_otp instead of being sent by SMS or email."""
    body.student_number = body.student_number.strip().upper()
    if body.portal == "student" and not STUDENT_NUMBER_RE.match(body.student_number):
        raise HTTPException(422, "Student number format is YYYY-NNNNN-CM-N, for example 2020-00000-CM-0")
    secs = lock_remaining(body.student_number)
    if secs:
        raise HTTPException(429, lock_message(secs))
    user = db.scalar(select(User).where(User.student_number == body.student_number))
    if not user or not verify_password(body.password, user.password_hash):
        locked = register_fail(body.student_number)
        audit(db, body.student_number, "", "login_failed", "Wrong student number or password" + (" - account locked for 5 minutes" if locked else ""), ok=False)
        if locked:
            raise HTTPException(429, lock_message(LOCK_SECONDS))
        raise HTTPException(401, "Invalid student number or password")
    if body.portal and body.portal != user.role:
        audit(db, user.student_number, user.role, "login_failed", "Used the wrong login portal", ok=False)
        raise HTTPException(403, "This is an administrator account. Use the Administrator login." if user.role == "admin"
                            else "This is a student account. Use the Student login.")
    user.otp_counter += 1
    user.otp_pending = True
    db.commit()
    audit(db, user.student_number, user.role, "password_ok", "Password accepted, OTP issued")
    return {"otp_token": make_token(user, "otp", 5),
            "dev_otp": hotp(user.otp_secret, user.otp_counter),
            "note": "Simulated OTP delivery (prototype)"}


@app.post("/auth/verify-otp")
def verify_otp(body: OtpIn, db: Session = Depends(get_db)):
    """Step 2: verify the HOTP, then issue the JWT access token."""
    try:
        p = jwt.decode(body.otp_token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "OTP session expired. Log in again.")
    if p.get("scope") != "otp":
        raise HTTPException(401, "Invalid token scope")
    user = db.get(User, int(p["sub"]))
    if not user or not user.otp_pending:
        raise HTTPException(401, "No pending OTP. Log in again.")
    secs = lock_remaining(user.student_number)
    if secs:
        raise HTTPException(429, lock_message(secs))
    if not hmac.compare_digest(hotp(user.otp_secret, user.otp_counter), body.code.strip()):
        locked = register_fail(user.student_number)
        audit(db, user.student_number, user.role, "otp_failed", "Incorrect OTP" + (" - account locked for 5 minutes" if locked else ""), ok=False)
        if locked:
            user.otp_pending = False
            db.commit()
            raise HTTPException(429, lock_message(LOCK_SECONDS))
        raise HTTPException(401, "Incorrect OTP")
    user.otp_pending = False  # single use
    db.commit()
    clear_fails(user.student_number)
    audit(db, user.student_number, user.role, "login", "Signed in")
    return {"access_token": make_token(user, "access", 60), "token_type": "bearer",
            "user": {"student_number": user.student_number, "full_name": user.full_name,
                     "program": user.program, "role": user.role, "respondent_code": user.respondent_code}}


@app.get("/election")
def election(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return election_out(get_election(db))


@app.put("/admin/election/status")
def set_status(body: StatusIn, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    if body.status not in ("upcoming", "open", "closed"):
        raise HTTPException(422, "status must be upcoming, open, or closed")
    e = get_election(db)
    old = e.status
    e.status = body.status
    db.commit()
    audit(db, admin.student_number, "admin", "election_status", f"{old} -> {body.status}")
    notify("election", "results")
    return election_out(e)


@app.get("/candidates")
def list_candidates(user: User = Depends(current_user), db: Session = Depends(get_db)):
    e = get_election(db)
    rows = db.scalars(select(Candidate).where(Candidate.election_id == e.id).order_by(Candidate.id)).all()
    return [candidate_out(c, user.role == "admin") for c in rows]


@app.get("/candidates/{candidate_id}")
def get_candidate(candidate_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    c = db.get(Candidate, candidate_id)
    if not c:
        raise HTTPException(404, "Candidate not found")
    return candidate_out(c, user.role == "admin")


# ----- Credibility checker (admin) -----
@app.put("/admin/candidates/{candidate_id}/scores")
def set_scores(candidate_id: int, body: ScoresIn, admin: User = Depends(require_role("admin")),
               db: Session = Depends(get_db)):
    """Administrator enters verified achievements, leadership experience, and community involvement
    scores (0-100) from the candidate's validated documents. The Credibility Score is then recomputed."""
    c = db.get(Candidate, candidate_id)
    if not c:
        raise HTTPException(404, "Candidate not found")
    c.achievements_score = body.achievements_score
    c.leadership_score = body.leadership_score
    c.community_score = body.community_score
    db.commit()
    recompute_credibility(db, c.election_id)
    db.refresh(c)
    notify("candidates", "results")
    return candidate_out(c, True)


@app.post("/admin/credibility/recompute")
def recompute(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    e = get_election(db)
    notify("candidates")
    return [candidate_out(c, True) for c in recompute_credibility(db, e.id)]


@app.get("/admin/flagged")
def flagged_manifestos(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Manifestos at or above the 0.70 similarity threshold, for administrator review.
    A flag never rejects a candidate by itself."""
    e = get_election(db)
    rows = db.scalars(select(Candidate).where(Candidate.election_id == e.id, Candidate.flagged == True)  # noqa: E712
                      .order_by(Candidate.id)).all()
    return {"threshold": scoring.FLAG_THRESHOLD, "flagged": [candidate_out(c, True) for c in rows]}


# ----- Announcements -----
@app.get("/announcements")
def list_announcements(user: User = Depends(current_user), db: Session = Depends(get_db)):
    e = get_election(db)
    rows = db.scalars(select(Announcement).where(Announcement.election_id == e.id)
                      .order_by(Announcement.created_at.desc())).all()
    return [{"id": a.id, "title": a.title, "body": a.body, "created_at": a.created_at.isoformat()} for a in rows]


@app.post("/announcements")
def create_announcement(body: AnnouncementIn, admin: User = Depends(require_role("admin")),
                        db: Session = Depends(get_db)):
    e = get_election(db)
    a = Announcement(election_id=e.id, title=body.title, body=body.body)
    db.add(a)
    db.commit()
    audit(db, admin.student_number, "admin", "announcement", a.title)
    notify("announcements")
    return {"id": a.id, "title": a.title, "body": a.body, "created_at": a.created_at.isoformat()}


# ----- Voting -----
@app.get("/vote/status")
def vote_status(student: User = Depends(require_role("student")), db: Session = Depends(get_db)):
    e = get_election(db)
    v = db.scalar(select(Vote).where(Vote.election_id == e.id, Vote.student_number == student.student_number))
    return {"has_voted": v is not None, "transaction_id": v.transaction_id if v else None}


@app.post("/vote")
def cast_vote(body: VoteIn, student: User = Depends(require_role("student")), db: Session = Depends(get_db)):
    """One-student-one-vote via Transaction ID Verification."""
    e = get_election(db)
    if e.status != "open":
        raise HTTPException(403, f"Voting is not open (status: {e.status})")
    c = db.get(Candidate, body.candidate_id)
    if not c or c.election_id != e.id:
        raise HTTPException(404, "Candidate not found in this election")
    tx = transaction_id(student.student_number, e.id)
    if db.scalar(select(Vote).where(Vote.transaction_id == tx)):
        raise HTTPException(409, "You have already voted")
    try:
        db.add(Vote(election_id=e.id, candidate_id=c.id, student_number=student.student_number, transaction_id=tx))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "You have already voted")
    audit(db, student.student_number, "student", "vote_cast", "Vote recorded (choice not logged here)")
    notify("results")
    return {"message": "Vote recorded", "transaction_id": tx}


# ----- Tallying and results -----
@app.get("/results")
def results(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Hash Map tally, then Quick Sort in descending order of votes. Also returns turnout
    so the app can draw the real-time pie/bar charts."""
    e = get_election(db)
    cands = db.scalars(select(Candidate).where(Candidate.election_id == e.id)).all()
    names = {c.id: c.full_name for c in cands}
    cast = db.scalars(select(Vote.candidate_id).where(Vote.election_id == e.id)).all()
    tally = scoring.count_votes(list(names.keys()), list(cast))
    ranked = scoring.ranked_results(tally)
    total = len(cast)
    eligible = db.scalar(select(func.count()).select_from(User).where(User.role == "student")) or 0
    return {
        "election": election_out(e),
        "turnout": {"votes_cast": total, "eligible_voters": eligible,
                    "turnout_percent": round(total / eligible * 100, 2) if eligible else 0.0},
        "results": [{"rank": i + 1, "candidate_id": cid, "full_name": names[cid], "votes": v,
                     "percent": round(v / total * 100, 2) if total else 0.0}
                    for i, (cid, v) in enumerate(ranked)],
    }


# ---------------- Health and live sync endpoints ----------------
_autoclose_task: asyncio.Task | None = None


def _autoclose_check():
    db = SessionLocal()
    try:
        e = db.scalar(select(Election).order_by(Election.id))
        if e:
            maybe_autoclose(db, e)
    finally:
        db.close()


async def _autoclose_loop():
    while True:
        await asyncio.sleep(10)
        try:
            await asyncio.to_thread(_autoclose_check)
        except Exception:
            pass


def _apply_admin_password():
    """If VOTERA_ADMIN_PASSWORD is set, the administrator account uses that password (applied on every start,
    so it can be changed from the hosting dashboard without re-seeding). The password never appears in code."""
    pw = os.getenv("VOTERA_ADMIN_PASSWORD")
    if not pw:
        return
    db = SessionLocal()
    try:
        admin = db.scalar(select(User).where(User.role == "admin").order_by(User.id))
        if admin and not verify_password(pw, admin.password_hash):
            admin.password_hash = hash_password(pw)
            db.commit()
            audit(db, "system", "", "admin_password", "Administrator password updated from the server settings")
    finally:
        db.close()


@app.on_event("startup")
async def _capture_loop():
    global _autoclose_task
    await asyncio.to_thread(_apply_admin_password)
    manager.loop = asyncio.get_running_loop()
    _autoclose_task = asyncio.create_task(_autoclose_loop())


@app.on_event("shutdown")
async def _stop_loop():
    if _autoclose_task:
        _autoclose_task.cancel()


@app.get("/health")
def health():
    """Light check with no database call. Used by the uptime monitor, so an idle database can stay asleep."""
    return {"status": "ok", "election": None}


@app.get("/health/db")
def health_db(db: Session = Depends(get_db)):
    """Full check including the database. The app calls it once at start so the server and database wake up
    while the student is still typing the login."""
    e = db.scalar(select(Election).order_by(Election.id))
    return {"status": "ok", "election": e.status if e else None}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    """First message must be {"token": "<JWT access token>"}. After that the server pushes
    {"type": "changed", "topics": [...]} whenever votes, status, candidates or announcements change."""
    await ws.accept()
    try:
        first = await asyncio.wait_for(ws.receive_json(), timeout=10)
        p = jwt.decode(first.get("token", ""), SECRET_KEY, algorithms=["HS256"])
        if p.get("scope") != "access":
            raise ValueError("scope")
    except Exception:
        await ws.close(code=4401)
        return
    manager.clients.add(ws)
    await ws.send_json({"type": "ready"})
    try:
        while True:
            await ws.receive_text()  # keeps the connection open; "ping" messages are accepted and ignored
    except WebSocketDisconnect:
        pass
    finally:
        manager.clients.discard(ws)


# ---------------- Admin: candidates ----------------
def _apply_candidate(c: Candidate, b: CandidateIn):
    for f in ("full_name", "program", "position", "manifesto", "achievements", "leadership", "community",
              "achievements_score", "leadership_score", "community_score", "video_url", "qa"):
        v = getattr(b, f)
        if f in ("video_url", "qa") and isinstance(v, str):
            v = v.strip() or None
        setattr(c, f, v)


@app.post("/admin/candidates")
def add_candidate(body: CandidateIn, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Add a candidate. TF-IDF similarity and credibility are recomputed for the whole field, because a new
    manifesto changes the reference set (and the IDF weights) for everyone."""
    e = get_election(db)
    if e.status == "open" and db.scalar(select(func.count()).select_from(Vote).where(Vote.election_id == e.id)):
        raise HTTPException(409, "Votes have already been cast. Reset the election before changing candidates.")
    c = Candidate(election_id=e.id)
    _apply_candidate(c, body)
    db.add(c)
    db.commit()
    audit(db, admin.student_number, "admin", "candidate_added", body.full_name)
    recompute_credibility(db, e.id)
    db.refresh(c)
    notify("candidates", "results")
    return candidate_out(c, True)


@app.put("/admin/candidates/{candidate_id}")
def edit_candidate(candidate_id: int, body: CandidateIn, admin: User = Depends(require_role("admin")),
                   db: Session = Depends(get_db)):
    c = db.get(Candidate, candidate_id)
    if not c:
        raise HTTPException(404, "Candidate not found")
    _apply_candidate(c, body)
    db.commit()
    audit(db, admin.student_number, "admin", "candidate_edited", c.full_name)
    recompute_credibility(db, c.election_id)
    db.refresh(c)
    notify("candidates", "results")
    return candidate_out(c, True)


@app.delete("/admin/candidates/{candidate_id}")
def delete_candidate(candidate_id: int, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    c = db.get(Candidate, candidate_id)
    if not c:
        raise HTTPException(404, "Candidate not found")
    if db.scalar(select(func.count()).select_from(Vote).where(Vote.candidate_id == c.id)):
        raise HTTPException(409, "This candidate already has votes. Reset the election to remove them.")
    eid = c.election_id
    nm = c.full_name
    db.delete(c)
    db.commit()
    audit(db, admin.student_number, "admin", "candidate_deleted", nm)
    recompute_credibility(db, eid)
    notify("candidates", "results")
    return {"deleted": candidate_id}


# ---------------- Admin: vote audit, voters, turnout, export, reset ----------------
def _audit_rows(db: Session, e: Election) -> list[dict]:
    names = {c.id: c.full_name for c in db.scalars(select(Candidate).where(Candidate.election_id == e.id))}
    users = {u.student_number: u for u in db.scalars(select(User).where(User.role == "student"))}
    votes = db.scalars(select(Vote).where(Vote.election_id == e.id).order_by(Vote.cast_at.desc())).all()
    return [{"student_number": v.student_number,
             "full_name": users[v.student_number].full_name if v.student_number in users else "",
             "program": users[v.student_number].program if v.student_number in users else "",
             "candidate_id": v.candidate_id, "candidate_name": names.get(v.candidate_id, "?"),
             "transaction_id": v.transaction_id, "cast_at": v.cast_at.isoformat()} for v in votes]


@app.get("/admin/votes")
def vote_audit(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Administrator-only audit: who voted for whom. Students never receive this."""
    return _audit_rows(db, get_election(db))


@app.get("/admin/voters")
def voter_list(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    e = get_election(db)
    voted = {v.student_number: v.cast_at for v in db.scalars(select(Vote).where(Vote.election_id == e.id))}
    rows = db.scalars(select(User).where(User.role == "student").order_by(User.student_number)).all()
    return [{"student_number": u.student_number, "full_name": u.full_name, "program": u.program,
             "respondent_code": u.respondent_code, "has_voted": u.student_number in voted,
             "voted_at": voted[u.student_number].isoformat() if u.student_number in voted else None} for u in rows]


@app.get("/admin/turnout")
def turnout_by_program(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    e = get_election(db)
    voted = set(db.scalars(select(Vote.student_number).where(Vote.election_id == e.id)))
    per: dict[str, dict] = {}
    for u in db.scalars(select(User).where(User.role == "student")):
        row = per.setdefault(u.program, {"program": u.program, "eligible": 0, "voted": 0})
        row["eligible"] += 1
        row["voted"] += 1 if u.student_number in voted else 0
    out = sorted(per.values(), key=lambda r: r["program"])
    for r in out:
        r["percent"] = round(r["voted"] / r["eligible"] * 100, 2) if r["eligible"] else 0.0
    return out


@app.get("/admin/export/votes.csv")
def export_votes(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["student_number", "full_name", "program", "candidate", "transaction_id", "cast_at"])
    for r in _audit_rows(db, get_election(db)):
        w.writerow([r["student_number"], r["full_name"], r["program"], r["candidate_name"],
                    r["transaction_id"], r["cast_at"]])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=votera_votes.csv"})


@app.post("/admin/election/reset")
def reset_election(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Clears all votes and sets the election back to upcoming so the simulation can be rerun."""
    e = get_election(db)
    n = db.query(Vote).filter(Vote.election_id == e.id).delete()
    e.status = "upcoming"
    e.closes_at = None
    db.commit()
    audit(db, admin.student_number, "admin", "election_reset", f"{n} votes removed")
    notify("election", "results", "candidates")
    return {"votes_removed": n, "status": e.status}


class DemoIn(BaseModel):
    count: int = Field(default=20, ge=1, le=250)


@app.post("/admin/demo/fill")
def demo_fill(body: DemoIn, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Demo mode: casts votes for students who have not voted yet, so the live charts can be shown during a
    demonstration. Uses the same one-vote rule and SHA-256 transaction IDs. Reset the election afterwards."""
    import random
    e = get_election(db)
    if e.status != "open":
        raise HTTPException(403, "Open the election first")
    cids = [c.id for c in db.scalars(select(Candidate).where(Candidate.election_id == e.id))]
    if not cids:
        raise HTTPException(409, "No candidates")
    voted = set(db.scalars(select(Vote.student_number).where(Vote.election_id == e.id)))
    pool = [u for u in db.scalars(select(User).where(User.role == "student").order_by(User.student_number))
            if u.student_number not in voted]
    random.shuffle(pool)
    added = 0
    for u in pool[:body.count]:
        db.add(Vote(election_id=e.id, candidate_id=random.choice(cids), student_number=u.student_number,
                    transaction_id=transaction_id(u.student_number, e.id)))
        added += 1
    db.commit()
    audit(db, admin.student_number, "admin", "demo_fill", f"{added} demo votes added")
    notify("results")
    return {"added": added}


# ---------------- Candidate photos ----------------
@app.get("/candidates/{candidate_id}/photo")
def get_photo(candidate_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    c = db.get(Candidate, candidate_id)
    if not c or not c.photo:
        raise HTTPException(404, "No photo")
    return Response(c.photo, media_type=c.photo_type or "image/jpeg", headers={"Cache-Control": "private, max-age=3600"})


@app.put("/admin/candidates/{candidate_id}/photo")
async def put_photo(candidate_id: int, request: Request, admin: User = Depends(require_role("admin")),
                    db: Session = Depends(get_db)):
    """Body is the raw image bytes (JPEG or PNG, up to 2 MB). The app shrinks photos before sending."""
    data = await request.body()
    if len(data) > 2_000_000:
        raise HTTPException(413, "Photo is too large (max 2 MB)")
    if data[:3] == b"\xff\xd8\xff":
        kind = "image/jpeg"
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        kind = "image/png"
    else:
        raise HTTPException(415, "Use a JPEG or PNG image")
    c = db.get(Candidate, candidate_id)
    if not c:
        raise HTTPException(404, "Candidate not found")
    c.photo, c.photo_type, c.photo_version = data, kind, (c.photo_version or 0) + 1
    db.commit()
    notify("candidates")
    return candidate_out(c, True)


@app.delete("/admin/candidates/{candidate_id}/photo")
def delete_photo(candidate_id: int, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    c = db.get(Candidate, candidate_id)
    if not c:
        raise HTTPException(404, "Candidate not found")
    c.photo, c.photo_type, c.photo_version = None, None, (c.photo_version or 0) + 1
    db.commit()
    notify("candidates")
    return candidate_out(c, True)


# ---------------- Admin: add voters from a spreadsheet (CSV) ----------------
VOTER_COLUMNS = "student_number,full_name,program,password"
_ALIASES = {"student_number": "student_number", "studentnumber": "student_number", "student_no": "student_number",
            "student_no.": "student_number", "full_name": "full_name", "fullname": "full_name", "name": "full_name",
            "program": "program", "course": "program", "password": "password"}
MAX_IMPORT_ROWS = 200


class ImportIn(BaseModel):
    csv: str = Field(max_length=400_000)


@app.post("/admin/voters/import")
def import_voters(body: ImportIn, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Adds student voter accounts from CSV text (export any Google Sheets or Excel sheet as CSV).
    Required columns: student_number, full_name, program. Optional: password (blank = a random one is generated
    and returned once so it can be handed to the student). Every row is checked; bad rows are reported and skipped."""
    text = body.csv.lstrip("\ufeff")
    first = text.splitlines()[0] if text.strip() else ""
    delim = max([",", ";", "\t"], key=lambda d: first.count(d))
    rows = [r for r in csv.reader(io.StringIO(text), delimiter=delim) if any(c.strip() for c in r)]
    if not rows:
        raise HTTPException(422, "The file is empty")
    header = [h.strip().lower().replace(" ", "_") for h in rows[0]]
    cols = {_ALIASES[h]: i for i, h in enumerate(header) if h in _ALIASES}
    missing = [c for c in ("student_number", "full_name", "program") if c not in cols]
    if missing:
        raise HTTPException(422, f"Missing column(s): {', '.join(missing)}. The first row must be: {VOTER_COLUMNS}")
    data = rows[1:]
    if not data:
        raise HTTPException(422, "The file has a header row but no students")
    if len(data) > MAX_IMPORT_ROWS:
        raise HTTPException(422, f"Too many rows ({len(data)}). Upload at most {MAX_IMPORT_ROWS} students at a time.")
    prog_lookup = {p.lower(): p for p in PROGRAMS}
    existing = set(db.scalars(select(User.student_number)))
    code_no = next_respondent_code(db)
    seen: set[str] = set()
    errors, generated, created = [], [], 0
    hash_cache: dict[str, str] = {}

    def cell(r, name):
        i = cols.get(name)
        return r[i].strip() if i is not None and i < len(r) else ""

    for n, r in enumerate(data, start=2):  # row 1 is the header
        sn = cell(r, "student_number").upper()
        name = cell(r, "full_name")
        prog = prog_lookup.get(cell(r, "program").lower())
        pw = cell(r, "password")
        reason = None
        if not STUDENT_NUMBER_RE.match(sn):
            reason = "student number must look like 2020-00000-CM-0"
        elif not name:
            reason = "name is empty"
        elif prog is None:
            reason = "unknown program (use one of: " + "; ".join(PROGRAMS) + ")"
        elif pw and len(pw) < 6:
            reason = "password must be at least 6 characters (or leave it blank)"
        elif sn in existing:
            reason = "already has an account"
        elif sn in seen:
            reason = "listed twice in this file"
        if reason:
            errors.append({"row": n, "student_number": sn, "reason": reason})
            continue
        seen.add(sn)
        if not pw:
            pw = secrets.token_urlsafe(6)
            generated.append({"student_number": sn, "full_name": name, "password": pw})
        if pw not in hash_cache:
            hash_cache[pw] = hash_password(pw, rounds=10)
        db.add(User(student_number=sn, full_name=name, program=prog, password_hash=hash_cache[pw],
                    role="student", otp_secret=secrets.token_hex(10), respondent_code=f"R-{code_no:03d}"))
        code_no += 1
        created += 1
    db.commit()
    audit(db, admin.student_number, "admin", "voters_import", f"{created} created, {len(errors)} skipped")
    if created:
        notify("results", "voters")
    return {"created": created, "skipped": len(errors), "errors": errors[:50], "generated": generated}


@app.get("/admin/voters/format")
def voter_format(admin: User = Depends(require_role("admin"))):
    """The exact format the upload expects, so the app can show it as a guide."""
    return {"columns": VOTER_COLUMNS, "programs": PROGRAMS, "max_rows": MAX_IMPORT_ROWS,
            "example": VOTER_COLUMNS + "\n2022-90251-CM-0,Juan Dela Cruz,BSIT,\n2022-90252-CM-0,Maria Santos,BSBA - HRM,mypass123"}


# ---------------- Admin: voting schedule and credentials sheet ----------------
class ScheduleIn(BaseModel):
    minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 14)  # None clears the closing time


@app.put("/admin/election/schedule")
def set_schedule(body: ScheduleIn, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Optional automatic close: the election closes by itself this many minutes from now."""
    e = get_election(db)
    e.closes_at = (now_naive() + timedelta(minutes=body.minutes)) if body.minutes else None
    db.commit()
    audit(db, admin.student_number, "admin", "schedule", f"closes in {body.minutes} min" if body.minutes else "automatic closing cleared")
    notify("election")
    return election_out(e)


class CredentialsIn(BaseModel):
    program: str | None = None  # limit to one program; None = every student


@app.post("/admin/credentials/regenerate")
def regenerate_credentials(body: CredentialsIn, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Creates a NEW random password for the chosen students and returns the sheet to hand out. Passwords are stored
    only as bcrypt hashes, so this is the only moment the plain text exists. Old passwords stop working."""
    q = select(User).where(User.role == "student").order_by(User.student_number)
    if body.program:
        q = q.where(User.program == body.program)
    rows = []
    for u in db.scalars(q):
        pw = secrets.token_urlsafe(6)
        u.password_hash = hash_password(pw, rounds=10)
        rows.append({"student_number": u.student_number, "full_name": u.full_name, "program": u.program,
                     "respondent_code": u.respondent_code, "password": pw})
    db.commit()
    audit(db, admin.student_number, "admin", "credentials_sheet", f"{len(rows)} new passwords generated")
    return {"count": len(rows), "rows": rows}


# ---------------- Admin: audit log ----------------
@app.get("/admin/audit-log")
def audit_log(limit: int = 100, only_problems: bool = False, admin: User = Depends(require_role("admin")),
              db: Session = Depends(get_db)):
    """Newest first. Read-only; there is no endpoint that edits or deletes entries."""
    q = select(AuditLog).order_by(AuditLog.id.desc()).limit(max(1, min(limit, 300)))
    if only_problems:
        q = select(AuditLog).where(AuditLog.ok == False).order_by(AuditLog.id.desc()).limit(max(1, min(limit, 300)))  # noqa: E712
    return [{"id": r.id, "at": r.at.isoformat() + ("Z" if r.at.tzinfo is None else ""), "actor": r.actor, "role": r.role,
             "action": r.action, "detail": r.detail, "ok": r.ok} for r in db.scalars(q)]


# ---------------- Admin: self-test of the Chapter 3 methods ----------------
@app.get("/admin/selftest")
def selftest(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Runs the project's core methods on known inputs and reports pass or fail. Nothing in the real
    election data is changed (the one-vote check uses a throwaway in-memory database)."""
    checks: list[dict] = []

    def check(group: str, name: str, fn):
        try:
            res = fn()
            ok, detail = (res if isinstance(res, tuple) else (bool(res), ""))
        except Exception as ex:  # a crash is a failed check, not a failed request
            ok, detail = False, f"error: {ex}"
        checks.append({"group": group, "name": name, "ok": bool(ok), "detail": detail})

    # Security
    def t_bcrypt():
        h = hash_password("sample-pass", rounds=4)
        return (h != "sample-pass" and verify_password("sample-pass", h) and not verify_password("other", h),
                "Stored as a salted hash, correct password accepted, wrong one rejected")
    check("Security", "bcrypt password hashing", t_bcrypt)

    def t_hotp():
        got = [hotp("12345678901234567890", i) for i in range(3)]
        return got == ["755224", "287082", "359152"], f"RFC 4226 test values: {', '.join(got)}"
    check("Security", "HOTP one-time password (RFC 4226 test values)", t_hotp)

    def t_jwt():
        u = User(id=0, student_number="x", role="student", otp_secret="x")
        t = make_token(u, "access", 5)
        good = jwt.decode(t, SECRET_KEY, algorithms=["HS256"])["scope"] == "access"
        try:
            jwt.decode(t[:-2] + ("AA" if not t.endswith("AA") else "BB"), SECRET_KEY, algorithms=["HS256"])
            bad_rejected = False
        except jwt.PyJWTError:
            bad_rejected = True
        return good and bad_rejected, "Valid token accepted, altered token rejected"
    check("Security", "JWT session token", t_jwt)

    def t_rbac():
        dep = require_role("admin")
        try:
            dep(User(id=0, student_number="s", role="student", otp_secret="x"))
            return False, "A student was allowed through"
        except HTTPException as ex:
            return ex.status_code == 403, "A student account is refused on admin functions (403)"
    check("Security", "Role-based access control", t_rbac)

    def t_lock():
        k = "__selftest__"
        clear_fails(k)
        res = [register_fail(k) for _ in range(MAX_FAILS)]
        locked = lock_remaining(k) > 0
        clear_fails(k)
        return res[-1] and not any(res[:-1]) and locked, f"Account locks after {MAX_FAILS} wrong attempts for {LOCK_SECONDS // 60} minutes"
    check("Security", "Failed-login lockout", t_lock)

    # Voting
    def t_tx():
        a, b = transaction_id("2022-90001-CM-0", 1), transaction_id("2022-90002-CM-0", 1)
        return (a == transaction_id("2022-90001-CM-0", 1) and a != b and len(a) == 64 and re.fullmatch("[0-9a-f]{64}", a) is not None,
                "SHA-256, 64 hex characters, same student gives the same ID, different students differ")
    check("Voting", "SHA-256 transaction ID", t_tx)

    def t_onevote():
        eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(eng)
        with Session(eng) as s2:
            s2.add(Vote(election_id=1, candidate_id=1, student_number="S-1", transaction_id="t1"))
            s2.commit()
            s2.add(Vote(election_id=1, candidate_id=2, student_number="S-1", transaction_id="t2"))
            try:
                s2.commit()
                return False, "A second vote by the same student was accepted"
            except IntegrityError:
                return True, "A second vote by the same student is refused by the database"
    check("Voting", "One student, one vote", t_onevote)

    def t_dupes():
        e = get_election(db)
        n_dupe = db.scalar(select(func.count()).select_from(
            select(Vote.student_number).where(Vote.election_id == e.id).group_by(Vote.student_number)
            .having(func.count() > 1).subquery()))
        return n_dupe == 0, f"{n_dupe} students with more than one vote in the real data"
    check("Voting", "No duplicate votes in the real data", t_dupes)

    # Tally and sorting
    def t_tally():
        e = get_election(db)
        cids = [c.id for c in db.scalars(select(Candidate).where(Candidate.election_id == e.id))]
        cast = list(db.scalars(select(Vote.candidate_id).where(Vote.election_id == e.id)))
        t = scoring.count_votes(cids, cast)
        sql = dict(db.execute(select(Vote.candidate_id, func.count()).where(Vote.election_id == e.id).group_by(Vote.candidate_id)).all())
        same = all(t.get(c, 0) == sql.get(c, 0) for c in cids) and sum(t.values()) == len(cast)
        return same, f"Hash map tally matches the database count ({len(cast)} votes)"
    check("Tally", "Hash map tally matches the database", t_tally)

    def t_sort():
        import random
        rnd = random.Random(7)
        data = [(i, rnd.randint(0, 30)) for i in range(60)]
        mine = scoring.ranked_results({a: b for a, b in data})
        ref = sorted(data, key=lambda p: (-p[1], p[0]))
        return mine == ref, "Hand-written Quick Sort ranks 60 random tallies from highest to lowest, same as a reference sort"
    check("Tally", "Quick Sort ranking", t_sort)

    # Credibility checker
    def t_cosine():
        same = scoring.compute_similarities(["improve student services and campus events",
                                             "improve student services and campus events",
                                             "build a recycling program for dormitories"])
        return same[0] > 0.99 and same[2] < 0.2, f"Identical manifestos: {same[0]:.2f}, different one: {same[2]:.2f}"
    check("Credibility", "TF-IDF and cosine similarity", t_cosine)

    check("Credibility", "Originality = 100 - similarity x 100",
          lambda: (scoring.originality_score(0.35) == 65.0 and scoring.originality_score(1.0) == 0.0, "0.35 gives 65, 1.00 gives 0"))
    check("Credibility", "Flag at 0.70 or higher (review only)",
          lambda: (scoring.is_flagged(0.70) and not scoring.is_flagged(0.699), "0.70 is flagged, 0.699 is not"))
    check("Credibility", "Weighted Sum Model (35/30/20/15)",
          lambda: (scoring.credibility_score(80, 70, 60, 50) == 68.5 and abs(sum(scoring.WEIGHTS.values()) - 1) < 1e-9,
                   "80, 70, 60, 50 gives 68.5 and the weights add up to 100%"))

    passed = sum(1 for c in checks if c["ok"])
    audit(db, admin.student_number, "admin", "selftest", f"{passed}/{len(checks)} checks passed", ok=passed == len(checks))
    return {"passed": passed, "total": len(checks), "checks": checks}