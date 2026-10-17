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
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)         # last successful sign-in (UTC)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)          # last request with a valid token (UTC, updated at most once a minute)
    tokens_valid_after: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # sessions started before this moment are ended


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
    published: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=True)  # False = draft, hidden from students (None counts as published)
    # Administrator-entered criterion scores (0-100)
    achievements_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    leadership_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    community_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    credibility_score: Mapped[float | None] = mapped_column(Float, nullable=True)


class Vote(Base):
    __tablename__ = "votes"
    # One vote per student per position (President, Vice President, Secretary, ...), not one vote in total.
    __table_args__ = (UniqueConstraint("election_id", "student_number", "position", name="one_vote_per_position"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    election_id: Mapped[int] = mapped_column(ForeignKey("elections.id"))
    candidate_id: Mapped[int] = mapped_column(ForeignKey("candidates.id"))
    position: Mapped[str | None] = mapped_column(String(80), nullable=True)
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
    category: Mapped[str | None] = mapped_column(String(30), nullable=True, default="General")
    pinned: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)
    image: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)  # optional picture on the post
    image_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    image_version: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    publish_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # scheduled posts stay hidden from students until this moment (UTC)


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


class Proof(Base):
    """A picture of a certificate or other document that backs up a candidate's achievements, leadership or community claim."""
    __tablename__ = "proofs"
    id: Mapped[int] = mapped_column(primary_key=True)
    candidate_id: Mapped[int] = mapped_column(ForeignKey("candidates.id"), index=True)
    category: Mapped[str] = mapped_column(String(16))             # achievements | leadership | community
    caption: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(10), default="verified")   # verified | rejected (rejected is hidden from students)
    mime: Mapped[str] = mapped_column(String(20), default="image/jpeg")
    data: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    issuer: Mapped[str | None] = mapped_column(String(80), nullable=True)       # who issued the certificate (school office, organization)
    issued_on: Mapped[str | None] = mapped_column(String(20), nullable=True)    # when, as the administrator writes it (2025, March 2025)
    verified_by: Mapped[str | None] = mapped_column(String(40), nullable=True)  # administrator who checked it
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Feedback(Base):
    """One short usability rating per student (the latest one replaces the earlier one). Used for the survey evidence."""
    __tablename__ = "feedback"
    id: Mapped[int] = mapped_column(primary_key=True)
    student_number: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    program: Mapped[str] = mapped_column(String(80), default="")
    ease: Mapped[int] = mapped_column(Integer, default=0)       # 1-5: easy to use
    clarity: Mapped[int] = mapped_column(Integer, default=0)    # 1-5: clear and understandable
    trust: Mapped[int] = mapped_column(Integer, default=0)      # 1-5: trust in the result
    overall: Mapped[int] = mapped_column(Integer, default=0)    # 1-5: overall satisfaction
    comment: Mapped[str] = mapped_column(String(500), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


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


def migrate_votes():
    """Older databases allowed one vote per student in total. Moves them to one vote per student per position
    (existing votes keep their candidate's position), without losing any votes."""
    insp = sa_inspect(engine)
    if not insp.has_table("votes"):
        return
    with engine.begin() as conn:
        conn.execute(sql_text("UPDATE votes SET position = (SELECT position FROM candidates WHERE candidates.id = votes.candidate_id) WHERE position IS NULL"))
        if engine.dialect.name == "postgresql":
            conn.execute(sql_text("ALTER TABLE votes DROP CONSTRAINT IF EXISTS one_student_one_vote"))
        conn.execute(sql_text("CREATE UNIQUE INDEX IF NOT EXISTS one_vote_per_position_idx ON votes (election_id, student_number, position)"))


migrate_votes()


def migrate_admin_number():
    """The administrator login stays ADMIN-001. If an earlier build renamed it to ADMIN-000, it is renamed back (same password)."""
    if not sa_inspect(engine).has_table("users"):
        return
    with engine.begin() as conn:
        if conn.execute(sql_text("SELECT 1 FROM users WHERE student_number = 'ADMIN-001'")).first() is None:
            conn.execute(sql_text("UPDATE users SET student_number = 'ADMIN-001' WHERE student_number = 'ADMIN-000' AND role = 'admin'"))


migrate_admin_number()


def migrate_position_names():
    """Older data used "SSC President". Drops the leading "SSC " from stored positions, so it is just "President"."""
    insp = sa_inspect(engine)
    with engine.begin() as conn:
        for table in ("candidates", "votes"):
            if insp.has_table(table):
                conn.execute(sql_text(f"UPDATE {table} SET position = SUBSTR(position, 5) WHERE position LIKE 'SSC %'"))


migrate_position_names()


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
               "iat": int(time.time()), "iatms": int(time.time() * 1000), "exp": utcnow() + timedelta(minutes=minutes)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def norm_pos(p: str | None) -> str:
    """Position text with extra spaces removed, for example "  Vice   President " -> "Vice President".
    A leading "SSC " is dropped ("SSC President" -> "President"), because the position is just the position."""
    t = " ".join((p or "").split())
    if t.lower().startswith("ssc ") and len(t) > 4:
        t = t[4:].strip()
    return t


def pos_key(p: str | None) -> str:
    return norm_pos(p).casefold()


# The PUPQC Student Council positions, in ballot order. Anything else the administrator types is a custom position and is listed after these.
SSC_POSITIONS = ["President", "Vice President", "Secretary-General", "Treasurer", "Auditor",
                 "Publicity and Communications Councilor (PCC)", "Creatives and Media Councilor (CMC)",
                 "Students' Rights and Welfare Councilor (STRAWC)", "Academics and Research Councilor (ARC)",
                 "Gender and Development Councilor (GADC)", "External Affairs and Partnership Councilor (EAPC)",
                 "Logistics and Technical Councilor (LTC)"]
_POS_ALIASES = {"ssc president": 0, "secretary": 2, "secretary general": 2, "pcc": 5, "cmc": 6, "strawc": 7, "arc": 8,
                "gadc": 9, "eapc": 10, "ltc": 11}


def position_rank(p: str) -> tuple[int, str]:
    """Position order on the ballot: the standard SSC list first, then custom positions A to Z."""
    k = pos_key(p)
    for i, n in enumerate(SSC_POSITIONS):
        if k == n.casefold():
            return (i, k)
    if k in _POS_ALIASES:
        return (_POS_ALIASES[k], k)
    if "vice" in k and "president" in k:
        return (1, k)
    if "president" in k:
        return (0, k)
    if "treasurer" in k:
        return (3, k)
    if "auditor" in k:
        return (4, k)
    return (100, k)


def is_published(c: "Candidate") -> bool:
    """A candidate is on the student ballot unless the administrator kept it as a draft (older rows have no value and count as published)."""
    return c.published is None or bool(c.published)


def ballot_candidates(db: Session, e: "Election") -> list:
    """The candidates students can see and vote for."""
    return [c for c in db.scalars(select(Candidate).where(Candidate.election_id == e.id).order_by(Candidate.id)) if is_published(c)]


def position_groups(cands: list) -> list[tuple[str, list]]:
    """Candidates grouped by position, in display order. Returns [(position name, [candidates])]."""
    groups: dict[str, tuple[str, list]] = {}
    for c in sorted(cands, key=lambda x: x.id):
        k = pos_key(c.position) or "candidate"
        groups.setdefault(k, (norm_pos(c.position) or "Candidate", []))[1].append(c)
    return sorted(groups.values(), key=lambda g: position_rank(g[0]))


def transaction_id(student_number: str, election_id: int, position: str = "") -> str:
    """SHA-256 transaction ID tied to the student number, the election and the position. Deterministic, so a
    second vote by the same student for the same position produces the same ID and is rejected."""
    base = f"{TX_SALT}|{student_number}|{election_id}"
    k = pos_key(position)
    return hashlib.sha256((base + (f"|{k}" if k else "")).encode()).hexdigest()


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
    if user.tokens_valid_after and int(p.get("iatms") or 0) <= int(user.tokens_valid_after.replace(tzinfo=timezone.utc).timestamp() * 1000):
        raise HTTPException(401, "Your session was ended by the administrator. Log in again.")
    now = now_naive()
    if not user.last_seen or (now - user.last_seen).total_seconds() > 60:
        user.last_seen = now       # shows who is online in Admin > Activity (written at most once a minute)
        db.commit()
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


class FeedbackIn(BaseModel):
    ease: int = Field(ge=1, le=5)
    clarity: int = Field(ge=1, le=5)
    trust: int = Field(ge=1, le=5)
    overall: int = Field(ge=1, le=5)
    comment: str = Field(default="", max_length=500)


class StatusIn(BaseModel):
    status: str


ANNOUNCEMENT_CATEGORIES = ["General", "Schedule", "Reminder", "Rules", "Results", "Urgent"]


class AnnouncementIn(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(default="", max_length=1000)
    category: str = "General"
    pinned: bool = False
    publish_in_minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 30)   # None = publish now


class AnnouncementEdit(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=120)
    body: str | None = Field(default=None, max_length=1000)
    category: str | None = None
    pinned: bool | None = None


class CandidateIn(BaseModel):
    full_name: str = Field(min_length=1, max_length=120)
    program: str = ""
    position: str = Field(default="President", max_length=80)
    manifesto: str = ""
    achievements: str = ""
    leadership: str = ""
    community: str = ""
    achievements_score: float | None = Field(default=None, ge=0, le=100)
    leadership_score: float | None = Field(default=None, ge=0, le=100)
    community_score: float | None = Field(default=None, ge=0, le=100)
    video_url: str | None = Field(default=None, max_length=300)
    qa: str | None = Field(default=None, max_length=4000)
    published: bool | None = None   # None = leave as it is (new candidates are published)


class PublishedIn(BaseModel):
    published: bool


class ScoresIn(BaseModel):
    achievements_score: float = Field(ge=0, le=100)
    leadership_score: float = Field(ge=0, le=100)
    community_score: float = Field(ge=0, le=100)


def candidate_out(c: Candidate, admin: bool = False) -> dict:
    d = _candidate_base(c)
    from sqlalchemy.orm import object_session
    sess = object_session(c)
    if sess is not None:   # how many proof documents (students count only the verified ones)
        q = select(func.count()).select_from(Proof).where(Proof.candidate_id == c.id)
        d["proof_count"] = int(sess.scalar(q if admin else q.where(Proof.status == "verified")) or 0)
        rows = sess.execute(select(Proof.category, func.count()).where(Proof.candidate_id == c.id, Proof.status == "verified").group_by(Proof.category)).all()
        by = {k: n for k, n in rows}
        d["proof_achievements"], d["proof_leadership"], d["proof_community"] = (int(by.get(k, 0)) for k in PROOF_CATEGORIES)
        if admin:   # written claims that no verified document backs up yet
            d["missing_proof"] = [k for k in PROOF_CATEGORIES if (getattr(c, k) or "").strip() and not by.get(k)]
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
            "photo_version": c.photo_version or 0, "video_url": c.video_url, "qa": c.qa, "published": is_published(c), "proof_count": 0,
            "proof_achievements": 0, "proof_leadership": 0, "proof_community": 0, "missing_proof": []}


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
    user.last_login = user.last_seen = now_naive()
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
    if user.role != "admin":
        rows = [c for c in rows if is_published(c)]
    return [candidate_out(c, user.role == "admin") for c in rows]


@app.get("/candidates/{candidate_id}")
def get_candidate(candidate_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    c = db.get(Candidate, candidate_id)
    if not c or (user.role != "admin" and not is_published(c)):
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
def _category(c: str | None) -> str:
    for k in ANNOUNCEMENT_CATEGORIES:
        if (c or "").strip().casefold() == k.casefold():
            return k
    return "General"


def announcement_out(a: Announcement) -> dict:
    return {"id": a.id, "title": a.title, "body": a.body, "created_at": a.created_at.isoformat(),
            "category": a.category or "General", "pinned": bool(a.pinned), "image_version": a.image_version or 0,
            "publish_at": a.publish_at.isoformat() + "Z" if a.publish_at else None,
            "scheduled": bool(a.publish_at and a.publish_at > now_naive())}


@app.get("/announcements")
def list_announcements(user: User = Depends(current_user), db: Session = Depends(get_db)):
    e = get_election(db)
    rows = db.scalars(select(Announcement).where(Announcement.election_id == e.id)
                      .order_by(func.coalesce(Announcement.pinned, False).desc(), Announcement.created_at.desc())).all()
    if user.role != "admin":   # students see a scheduled post only once its time has come
        now = now_naive()
        rows = [a for a in rows if not a.publish_at or a.publish_at <= now]
    return [announcement_out(a) for a in rows]


@app.post("/announcements")
def create_announcement(body: AnnouncementIn, admin: User = Depends(require_role("admin")),
                        db: Session = Depends(get_db)):
    e = get_election(db)
    due = now_naive() + timedelta(minutes=body.publish_in_minutes) if body.publish_in_minutes else None
    a = Announcement(election_id=e.id, title=body.title.strip(), body=body.body.strip(), category=_category(body.category),
                     pinned=body.pinned, image_version=0, publish_at=due)
    db.add(a)
    db.commit()
    audit(db, admin.student_number, "admin", "announcement", a.title + (f" (scheduled in {body.publish_in_minutes} min)" if due else ""))
    if not due:
        notify("announcements")
    return announcement_out(a)


@app.put("/admin/announcements/{announcement_id}")
def edit_announcement(announcement_id: int, body: AnnouncementEdit, admin: User = Depends(require_role("admin")),
                      db: Session = Depends(get_db)):
    a = db.get(Announcement, announcement_id)
    if not a:
        raise HTTPException(404, "Announcement not found")
    if body.title is not None:
        a.title = body.title.strip()
    if body.body is not None:
        a.body = body.body.strip()
    if body.category is not None:
        a.category = _category(body.category)
    if body.pinned is not None:
        a.pinned = body.pinned
    db.commit()
    audit(db, admin.student_number, "admin", "announcement_edit", a.title)
    notify("announcements")
    return announcement_out(a)


@app.delete("/admin/announcements/{announcement_id}")
def delete_announcement(announcement_id: int, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    a = db.get(Announcement, announcement_id)
    if not a:
        raise HTTPException(404, "Announcement not found")
    title = a.title
    db.delete(a)
    db.commit()
    audit(db, admin.student_number, "admin", "announcement_delete", title)
    notify("announcements")
    return {"deleted": announcement_id}


@app.get("/announcements/{announcement_id}/image")
def get_announcement_image(announcement_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = db.get(Announcement, announcement_id)
    if not a or not a.image or (user.role != "admin" and a.publish_at and a.publish_at > now_naive()):
        raise HTTPException(404, "No image")
    return Response(a.image, media_type=a.image_type or "image/jpeg", headers={"Cache-Control": "private, max-age=3600"})


@app.put("/admin/announcements/{announcement_id}/image")
async def put_announcement_image(announcement_id: int, request: Request, admin: User = Depends(require_role("admin")),
                                 db: Session = Depends(get_db)):
    """Body is the raw image bytes (JPEG or PNG, up to 2 MB). The app shrinks pictures before sending."""
    data = await request.body()
    if len(data) > 2_000_000:
        raise HTTPException(413, "Image is too large (max 2 MB)")
    if data[:3] == b"\xff\xd8\xff":
        kind = "image/jpeg"
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        kind = "image/png"
    else:
        raise HTTPException(415, "Use a JPEG or PNG image")
    a = db.get(Announcement, announcement_id)
    if not a:
        raise HTTPException(404, "Announcement not found")
    a.image, a.image_type, a.image_version = data, kind, (a.image_version or 0) + 1
    db.commit()
    notify("announcements")
    return announcement_out(a)


@app.delete("/admin/announcements/{announcement_id}/image")
def delete_announcement_image(announcement_id: int, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    a = db.get(Announcement, announcement_id)
    if not a:
        raise HTTPException(404, "Announcement not found")
    a.image, a.image_type, a.image_version = None, None, (a.image_version or 0) + 1
    db.commit()
    notify("announcements")
    return announcement_out(a)


@app.get("/announcement-categories")
def announcement_categories(user: User = Depends(current_user)):
    return ANNOUNCEMENT_CATEGORIES


# ----- Voting -----
def _own_votes(db: Session, e: Election, student_number: str) -> dict[str, Vote]:
    return {pos_key(v.position): v for v in db.scalars(
        select(Vote).where(Vote.election_id == e.id, Vote.student_number == student_number).order_by(Vote.cast_at))}


@app.get("/vote/status")
def vote_status(student: User = Depends(require_role("student")), db: Session = Depends(get_db)):
    """Which positions this student has voted for and which are still open. Only the student's own choices."""
    e = get_election(db)
    cands = ballot_candidates(db, e)
    names = {c.id: c.full_name for c in cands}
    mine = _own_votes(db, e, student.student_number)
    positions = []
    for name, group in position_groups(cands):
        v = mine.get(pos_key(name))
        positions.append({"position": name, "voted": v is not None, "candidate_id": v.candidate_id if v else None,
                          "candidate_name": names.get(v.candidate_id) if v else None,
                          "transaction_id": v.transaction_id if v else None,
                          "voted_at": v.cast_at.isoformat() if v else None})
    last = max(mine.values(), key=lambda v: v.cast_at) if mine else None
    return {"has_voted": bool(mine), "complete": bool(positions) and all(p["voted"] for p in positions),
            "transaction_id": last.transaction_id if last else None, "positions": positions}


@app.post("/vote")
def cast_vote(body: VoteIn, student: User = Depends(require_role("student")), db: Session = Depends(get_db)):
    """One vote per student per position, each with its own SHA-256 Transaction ID."""
    e = get_election(db)
    if e.status != "open":
        raise HTTPException(403, f"Voting is not open (status: {e.status})")
    c = db.get(Candidate, body.candidate_id)
    if not c or c.election_id != e.id or not is_published(c):
        raise HTTPException(404, "Candidate not found in this election")
    position = norm_pos(c.position) or "Candidate"
    mine = _own_votes(db, e, student.student_number)
    if pos_key(position) in mine:
        raise HTTPException(409, f"You have already voted for {position}")
    tx = transaction_id(student.student_number, e.id, position)
    if db.scalar(select(Vote).where(Vote.transaction_id == tx)):
        raise HTTPException(409, f"You have already voted for {position}")
    try:
        db.add(Vote(election_id=e.id, candidate_id=c.id, position=position, student_number=student.student_number, transaction_id=tx))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, f"You have already voted for {position}")
    audit(db, student.student_number, "student", "vote_cast", f"Vote recorded for {position} (choice not logged here)")
    notify("results")
    all_pos = {pos_key(g[0]) for g in position_groups(ballot_candidates(db, e))}
    done = all_pos.issubset(set(mine) | {pos_key(position)})
    return {"message": "Vote recorded", "transaction_id": tx, "position": position, "complete": done}


@app.get("/vote/verify")
def verify_receipt(tx: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Checks that a Transaction ID exists. Only the voter who owns it also sees which candidate it was for."""
    t = (tx or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", t):
        return {"valid": False, "message": "A Transaction ID has 64 letters and digits (0-9, a-f)."}
    v = db.scalar(select(Vote).where(Vote.transaction_id == t))
    if not v:
        return {"valid": False, "message": "No vote with this Transaction ID was found."}
    mine = v.student_number == user.student_number
    out = {"valid": True, "position": v.position or "", "cast_at": v.cast_at.isoformat() + ("Z" if v.cast_at.tzinfo is None else ""),
           "yours": mine, "message": "This vote is recorded."}
    if mine:
        c = db.get(Candidate, v.candidate_id)
        out["candidate_name"] = c.full_name if c else ""
    return out


@app.post("/feedback")
def submit_feedback(body: FeedbackIn, student: User = Depends(require_role("student")), db: Session = Depends(get_db)):
    f = db.scalar(select(Feedback).where(Feedback.student_number == student.student_number))
    if not f:
        f = Feedback(student_number=student.student_number)
        db.add(f)
    f.program = student.program or ""
    f.ease, f.clarity, f.trust, f.overall = body.ease, body.clarity, body.trust, body.overall
    f.comment = re.sub(r"\s+", " ", body.comment).strip()[:500]
    f.updated_at = utcnow()
    db.commit()
    audit(db, student.student_number, "student", "feedback", "Feedback submitted")
    return {"message": "Thank you for your feedback"}


@app.get("/feedback/mine")
def my_feedback(student: User = Depends(require_role("student")), db: Session = Depends(get_db)):
    f = db.scalar(select(Feedback).where(Feedback.student_number == student.student_number))
    if not f:
        return {"submitted": False}
    return {"submitted": True, "ease": f.ease, "clarity": f.clarity, "trust": f.trust, "overall": f.overall, "comment": f.comment}


@app.get("/admin/feedback")
def feedback_summary(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Averages and comments. Comments are shown without names (program only)."""
    rows = db.scalars(select(Feedback).order_by(Feedback.updated_at.desc())).all()
    n = len(rows)
    def avg(k): return round(sum(getattr(r, k) for r in rows) / n, 2) if n else 0.0
    return {"count": n, "ease": avg("ease"), "clarity": avg("clarity"), "trust": avg("trust"), "overall": avg("overall"),
            "comments": [{"program": r.program, "overall": r.overall, "comment": r.comment} for r in rows if r.comment]}


# ----- Tallying and results -----
@app.get("/results")
def results(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Per position: Hash Map tally, then Quick Sort in descending order of votes. Also returns turnout
    so the app can draw the real-time pie/bar charts. Students receive totals only."""
    e = get_election(db)
    cands = ballot_candidates(db, e)
    votes = db.execute(select(Vote.candidate_id, Vote.student_number).where(Vote.election_id == e.id)).all()
    rows = []
    groups = position_groups(cands)
    for name, group in groups:
        ids = [c.id for c in group]
        cast = [cid for cid, _ in votes if cid in set(ids)]
        tally = scoring.count_votes(ids, cast)
        ranked = scoring.ranked_results(tally)
        total = len(cast)
        names = {c.id: c.full_name for c in group}
        for i, (cid, v) in enumerate(ranked):
            rows.append({"position": name, "rank": i + 1, "candidate_id": cid, "full_name": names[cid], "votes": v,
                         "percent": round(v / total * 100, 2) if total else 0.0})
    voters = {sn for _, sn in votes}
    eligible = db.scalar(select(func.count()).select_from(User).where(User.role == "student")) or 0
    return {
        "election": election_out(e),
        "turnout": {"votes_cast": len(voters), "eligible_voters": eligible,
                    "turnout_percent": round(len(voters) / eligible * 100, 2) if eligible else 0.0},
        "positions": [g[0] for g in groups],
        "results": rows,
    }


# ---------------- Health and live sync endpoints ----------------
_autoclose_task: asyncio.Task | None = None


_last_sched_check = [None]


def _autoclose_check():
    db = SessionLocal()
    try:
        e = db.scalar(select(Election).order_by(Election.id))
        if e:
            maybe_autoclose(db, e)
        # a scheduled announcement just became due: tell every phone so it shows up without a manual refresh
        now = now_naive()
        prev = _last_sched_check[0] or (now - timedelta(seconds=15))
        _last_sched_check[0] = now
        if db.scalar(select(Announcement.id).where(Announcement.publish_at.is_not(None), Announcement.publish_at > prev, Announcement.publish_at <= now)):
            notify("announcements")
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


def _startup_samples():
    db = SessionLocal()
    try:
        ensure_student_accounts(db)
    except Exception:
        db.rollback()
    try:
        ensure_sample_candidates(db)
    except Exception:
        db.rollback()
    finally:
        db.close()


@app.on_event("startup")
async def _capture_loop():
    global _autoclose_task
    await asyncio.to_thread(_apply_admin_password)
    await asyncio.to_thread(_startup_samples)
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
              "achievements_score", "leadership_score", "community_score", "video_url", "qa", "published"):
        v = getattr(b, f)
        if f == "published" and v is None:
            continue
        if f in ("video_url", "qa") and isinstance(v, str):
            v = v.strip() or None
        if f == "position" and isinstance(v, str):
            v = norm_pos(v)
        setattr(c, f, v)


# ---------------- Fictional student accounts (top-up) ----------------
# Table 1 allocation across the eight programs (sums to 236), scaled up when more accounts are wanted.
TABLE1_ALLOCATION = [39, 19, 19, 41, 44, 37, 21, 16]
FIRST_NAMES = ["Juan", "Maria", "Jose", "Ana", "Mark", "Angela", "John", "Kimberly", "Carlo", "Jasmine", "Paolo", "Bianca",
               "Miguel", "Nicole", "Gabriel", "Rhea", "Joshua", "Camille", "Daniel", "Patricia", "Christian", "Sofia",
               "Ryan", "Katrina", "Emmanuel", "Louise", "Francis", "Trisha", "Adrian", "Mariel", "Vincent", "Danica",
               "Kenneth", "Jessa", "Rafael", "Ellaine", "Jerome", "Hannah", "Lance", "Aileen"]
LAST_NAMES = ["Santos", "Reyes", "Cruz", "Bautista", "Ocampo", "Garcia", "Mendoza", "Torres", "Tomas", "Andrada", "Castillo",
              "Flores", "Villanueva", "Ramos", "Aquino", "Dela Cruz", "Navarro", "Salazar", "Domingo", "Gonzales", "Lopez",
              "Pascual", "Soriano", "Rivera", "Valdez", "Mercado", "Aguilar", "Manalo", "Esguerra", "Corpuz", "Hernandez",
              "Perez", "Fernandez", "Diaz", "Morales", "Silva", "Padilla", "Macaraeg", "Lim", "Tan"]
STUDENT_TOTAL = int(os.getenv("VOTERA_STUDENT_ACCOUNTS", "500"))


def fictional_names(n: int, seed: int = 2026) -> list[str]:
    import random
    rng = random.Random(seed)
    pairs = [(f, l) for f in FIRST_NAMES for l in LAST_NAMES]
    rng.shuffle(pairs)
    return [f"{f} {l}" for f, l in pairs[:n]]


def account_programs(total: int) -> list[str]:
    """Program for each account number 1..total: the first 236-scaled share follows Table 1, the last 14 are spare testers."""
    spare = 14
    main_n = max(total - spare, 0)
    base = sum(TABLE1_ALLOCATION)
    raw = [a * main_n / base for a in TABLE1_ALLOCATION]
    counts = [int(x) for x in raw]
    for i in sorted(range(len(raw)), key=lambda i: raw[i] - counts[i], reverse=True)[:main_n - sum(counts)]:
        counts[i] += 1
    progs = [p for p, n in zip(PROGRAMS, counts) for _ in range(n)]
    return progs + [PROGRAMS[i % len(PROGRAMS)] for i in range(spare)]


def ensure_student_accounts(db: Session, total: int = None) -> int:
    """Adds the fictional accounts 2022-90001-CM-0 .. 2022-9NNNN-CM-0 that are missing (password student123), once per target size.
    Never touches existing accounts, votes or candidates. Set VOTERA_STUDENT_ACCOUNTS=0 to switch it off."""
    total = STUDENT_TOTAL if total is None else total
    if total <= 0:
        return 0
    marker = f"students_topup_{total}"
    if db.scalar(select(AuditLog.id).where(AuditLog.action == marker)):
        return 0
    if not db.scalar(select(User.id).where(User.role == "student")):
        return 0       # empty database: seed.py creates the accounts
    have = set(db.scalars(select(User.student_number)))
    codes = set(db.scalars(select(User.respondent_code)))
    progs, names, shared = account_programs(total), fictional_names(total), hash_password("student123")
    added = 0
    for i in range(1, total + 1):
        sn = f"2022-{90000 + i:05d}-CM-0"
        rc = f"R-{i:03d}"
        if sn in have:
            continue
        db.add(User(student_number=sn, full_name=names[i - 1], program=progs[i - 1], respondent_code=rc if rc not in codes else None,
                    password_hash=shared, role="student", otp_secret=secrets.token_hex(10)))
        added += 1
    db.commit()
    audit(db, "system", "", marker, f"{added} fictional student accounts added")
    return added



# Fictional candidates for all 12 SSC positions (two each), so a demo shows a full ballot. Names are invented.
# They are added once automatically (see ensure_sample_candidates) and can be edited or removed in the Admin tab.
# (position, name, program, manifesto, achievements, leadership, community, (achievements score, leadership score, community score))
SAMPLE_CANDIDATES = [
    ('President', 'Ana Reyes', 'BSIT', 'I will make student services faster and easier by bringing enrollment concerns, scholarship updates, and clearance steps into one clear online guide. I will also open a mental health desk with trained peer listeners and partner with the guidance office for regular wellness weeks.', "Dean's Lister, three semesters. Hackathon finalist, 2025.", 'Class president, 2nd year. Org vice president, 3rd year.', 'Led a donation drive for flood-affected families.', (90, 85, 80)),
    ('President', 'Miguel Santos', 'BSBA - HRM', 'I will push for a student council that listens first and acts fast. My platform focuses on free tutoring programs, a transparent budget report every month, and stronger support for student organizations across all programs. Every student deserves a voice, and I will make sure every concern reaches the administration.', 'Best Thesis Proposal, department level.', 'Org treasurer, 3rd year. Class secretary, 2nd year.', 'Volunteer in a campus tree-planting activity.', (70, 75, 60)),
    ('Vice President', 'Carla Mendoza', 'BSBA - MM', 'I will push for a student council that listens first and acts quickly. My platform focuses on free tutoring programs, a transparent budget report every month, and stronger support for student organizations across all programs. Every student deserves a voice, and I will make sure each concern reaches the administration.', 'Marketing case competition participant.', 'Class representative, 3rd year.', 'Joined a literacy outreach program.', (60, 65, 70)),
    ('Vice President', 'Paolo Villanueva', 'BS Entrepreneurship', 'My focus is campus life outside the classroom. I will organize quarterly sports fests and cultural nights, create a job fair with partner companies for graduating students, and set up a small business bazaar where student entrepreneurs can sell on campus at no cost.', 'Startup pitch competition, second place.', 'Org president, 3rd and 4th year.', 'Organized a livelihood training for a nearby community.', (75, 90, 85)),
    ('Secretary-General', 'Liza Navarro', 'BTLEd - ICT', 'I will work with the administration on safer walkways, better lighting, working restrooms, and accessible ramps and elevators for students with mobility needs. I will also press for fair canteen prices and a monthly open forum where students can question the council directly.', 'Academic excellence award, 2nd year.', 'Peer tutor coordinator. Class vice president, 3rd year.', 'Regular blood donation drive volunteer.', (85, 80, 90)),
    ('Secretary-General', 'Jose Ramos', 'BPA - Fiscal Administration', 'Council records should be easy for any student to read. I will post short minutes within two days of every meeting, keep one public calendar of council activities, and set up a suggestion box that is answered in writing every week.', 'Best in Public Speaking, 2nd year.', 'Org secretary, 3rd year.', 'Helped organize a school supplies giveaway.', (65, 70, 65)),
    ('Treasurer', 'Maria Cruz', 'DOMT - Medical Office Management', 'Every peso of council funds should have a receipt a student can see. I will publish a simple income and spending sheet each month, ask students to vote on how leftover funds are used, and cut costs on events by asking partner shops for discounts.', 'Scholar with high honors, 2nd and 3rd year.', 'Org auditor, 3rd year.', 'Joined a community health outreach.', (80, 70, 75)),
    ('Treasurer', 'Noel Bautista', 'BTLEd - Home Economics', 'I want a council that runs on fundraising, not on student fees. My plan is a cooking and baking sale each term, a recycling drive that turns used paper into funds, and a clear signboard that shows what each activity earned and what it cost.', 'Home economics skills competition, regional participant.', 'Class treasurer, 2nd and 3rd year.', 'Fed families during a relief operation.', (70, 65, 80)),
    ("Auditor", "Rafael Domingo", "BPA - Fiscal Administration", "I will check every council expense against its receipt and report the result to students each term. Any difference in the books will be written down, explained, and corrected within one week.", "Accounting quiz bee, second place.", "Class auditor, 2nd and 3rd year.", "Helped count funds for a school fair.", (78, 72, 66)),
    ("Auditor", "Teresa Villamor", "DOMT - Medical Office Management", "My plan is a yearly inventory of council property with photos and a shared list, plus a surprise cash count twice a semester so nothing is left to trust alone.", "Consistent honor student.", "Org auditor, 3rd year.", "Joined a clothing donation drive.", (82, 68, 70)),
    ("Publicity and Communications Councilor (PCC)", "Bianca Salazar", "BS Entrepreneurship", "Students should never learn about a council activity too late. I will send one weekly digest with dates, places and deadlines, and answer every message on the council page within a day.", "Campus journalism contest, finalist.", "Org publicity head, 3rd year.", "Wrote announcements for a feeding program.", (74, 76, 72)),
    ("Publicity and Communications Councilor (PCC)", "Dennis Aquino", "BSIT", "I want one clear place for every memo, form and announcement. A pinned info board in the app and printed copies near the main gate will keep both online and offline students informed.", "Best documentation award, capstone class.", "Class secretary, 2nd year.", "Typed and printed letters for a donation drive.", (70, 70, 68)),
    ("Creatives and Media Councilor (CMC)", "Camille Ferrer", "BSBA - MM", "Good posters and short videos get students to show up. I will build a simple design kit for the council, train volunteers in basic editing, and produce a highlight video after each big event.", "Poster design contest, first place.", "Creative team lead, org, 3rd year.", "Designed posters for a charity run.", (80, 74, 66)),
    ("Creatives and Media Councilor (CMC)", "Joaquin Medina", "BTLEd - ICT", "I will set up a small media corner with a camera, a mic and a lighting kit that any student group can borrow, and teach a free weekend workshop on audio and slide design.", "Video editing workshop, certificate.", "Sound crew head, school program.", "Handled the sound system at a community event.", (72, 78, 70)),
    ("Students' Rights and Welfare Councilor (STRAWC)", "Isabel Cordero", "BPA - Fiscal Administration", "Every student concern deserves a ticket number and an answer. I will review the online helpdesk daily, publish a monthly summary of reports and outcomes, and bring unresolved issues to the right office.", "Debate league, semifinalist.", "Class representative, 3rd year.", "Assisted students with scholarship paperwork.", (76, 80, 82)),
    ("Students' Rights and Welfare Councilor (STRAWC)", "Marco Dizon", "BSBA - HRM", "I will prepare a short student rights handbook in plain language and hold open consultations each month, so nobody has to guess what they are allowed to ask for.", "Leadership seminar graduate.", "Org vice president, 3rd year.", "Spoke at a barangay youth forum.", (68, 74, 76)),
    ("Academics and Research Councilor (ARC)", "Hannah Legaspi", "BSIT", "I will start a research buddy program that pairs upper-year students with beginners, share templates for proposals and surveys, and organize a small student research fair every year.", "Research paper presented at a student conference.", "Peer mentor, 3rd year.", "Tutored grade school learners on weekends.", (88, 76, 74)),
    ("Academics and Research Councilor (ARC)", "Eric Manalo", "BTLEd - Home Economics", "A study space and a printed reviewer shelf can help more students than one big event. I will ask for a quiet room, collect past reviewers, and run exam week study groups.", "Subject topnotcher, 2nd year.", "Study group organizer, 2nd year.", "Ran a free review session for freshmen.", (79, 66, 70)),
    ("Gender and Development Councilor (GADC)", "Patricia Soriano", "BS Entrepreneurship", "Everyone should feel safe in class and online. I will hold orientation sessions on respect and consent, set a private way to ask for help, and work with the guidance office on regular check-ins.", "Gender awareness seminar, speaker.", "Org advocacy officer, 3rd year.", "Helped organize an inclusivity week.", (74, 78, 84)),
    ("Gender and Development Councilor (GADC)", "Samuel Pineda", "BSBA - HRM", "I will make campus events open to all by checking schedules, restrooms and seating, and I will invite student groups to share their stories during a yearly culture night.", "Cultural night host, 2nd year.", "Class vice president, 2nd year.", "Volunteered at a community health fair.", (66, 72, 78)),
    ("External Affairs and Partnership Councilor (EAPC)", "Lorraine Estrada", "BSBA - MM", "I will send partnership proposals to local shops and companies, keep a public list of every sponsor and what they gave, and bring back internship leads for graduating students.", "Sales pitch competition, finalist.", "Org external officer, 3rd year.", "Raised supplies for a school gift giving.", (73, 79, 71)),
    ("External Affairs and Partnership Councilor (EAPC)", "Vincent Alonzo", "BPA - Fiscal Administration", "Strong partners start with clear letters and quick follow-ups. I will keep a contact directory, thank every sponsor in public, and invite other campuses to joint community projects.", "Public administration case study, second place.", "Class secretary, 3rd year.", "Coordinated a joint outreach with another school.", (70, 69, 77)),
    ("Logistics and Technical Councilor (LTC)", "Nathaniel Robles", "BSIT", "Events fail when the venue and the equipment are not ready. I will walk through every venue the day before, keep a checklist for the projector, the sound and the extension cords, and prepare floor plans in advance.", "Technical support volunteer, school program.", "Equipment in charge, org, 3rd year.", "Set up chairs and a stage for a community event.", (72, 80, 74)),
    ("Logistics and Technical Councilor (LTC)", "Gloria Tuazon", "BTLEd - ICT", "I will label all council equipment, maintain a borrowing log, and test every device before an event, then send a short post-event report listing what worked and what needs repair.", "Best in computer repair skills test.", "Tech committee member, 2nd year.", "Fixed computers for a barangay learning center.", (77, 70, 69)),
]


def _add_sample_candidates(db: Session, e: Election, names_only: bool = False) -> int:
    """Adds the fictional candidates that are not on the ballot yet (matched by name and position). Returns how many were added."""
    existing = {(c.full_name, pos_key(c.position or "")): c for c in db.scalars(select(Candidate).where(Candidate.election_id == e.id))}
    added = 0
    for pos, name, prog, man, ach, lead, comm, (sa, sl, sc) in SAMPLE_CANDIDATES:
        old = existing.get((name, pos_key(pos)))
        if old is not None:
            if not names_only and not (old.manifesto or "").strip():   # a name added without its description: fill it in
                old.manifesto, old.achievements, old.leadership, old.community = man, ach, lead, comm
                old.achievements_score, old.leadership_score, old.community_score = sa, sl, sc
                added += 1
            continue
        if names_only:   # name, program and position only; the description and scores are left blank for the administrator
            db.add(Candidate(election_id=e.id, full_name=name, program=prog, position=pos, manifesto="", achievements="", leadership="", community=""))
        else:
            db.add(Candidate(election_id=e.id, full_name=name, program=prog, position=pos, manifesto=man, achievements=ach, leadership=lead,
                             community=comm, achievements_score=sa, leadership_score=sl, community_score=sc))
        added += 1
    db.commit()
    if added:
        recompute_credibility(db, e.id)
    return added


def ensure_sample_candidates(db: Session) -> int:
    """Puts the fictional candidates for every position on the ballot, once. Skipped when votes already exist, when it was done before
    (so removing a sample candidate stays removed), or when VOTERA_AUTO_SAMPLES=0."""
    if os.getenv("VOTERA_AUTO_SAMPLES", "1") == "0":
        return 0
    e = db.scalar(select(Election).order_by(Election.id))
    if not e or db.scalar(select(func.count()).select_from(Vote).where(Vote.election_id == e.id)):
        return 0
    if db.scalar(select(AuditLog.id).where(AuditLog.action == "samples_seeded")):
        return 0
    added = _add_sample_candidates(db, e)
    audit(db, "system", "", "samples_seeded", f"{added} sample candidates added automatically")
    if added:
        notify("candidates", "results")
    return added


@app.post("/admin/demo/candidates")
def demo_candidates(names_only: bool = False, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Adds the fictional candidates that are missing (all 12 positions). Safe to repeat. Not allowed after votes are cast."""
    e = get_election(db)
    if db.scalar(select(func.count()).select_from(Vote).where(Vote.election_id == e.id)):
        raise HTTPException(409, "Votes have already been cast. Reset the election before adding sample candidates.")
    added = _add_sample_candidates(db, e, names_only)
    if added:
        audit(db, admin.student_number, "admin", "demo_candidates", f"{added} sample candidates added")
        notify("candidates", "results")
    return {"added": added}


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
    db.query(Proof).filter(Proof.candidate_id == c.id).delete()
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
             "position": v.position or "", "candidate_id": v.candidate_id, "candidate_name": names.get(v.candidate_id, "?"),
             "transaction_id": v.transaction_id, "cast_at": v.cast_at.isoformat()} for v in votes]


@app.get("/admin/votes")
def vote_audit(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Administrator-only audit: who voted for whom. Students never receive this."""
    return _audit_rows(db, get_election(db))


@app.get("/admin/voters")
def voter_list(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    e = get_election(db)
    voted: dict[str, datetime] = {}
    count: dict[str, int] = {}
    for v in db.scalars(select(Vote).where(Vote.election_id == e.id)):
        voted[v.student_number] = max(voted.get(v.student_number, v.cast_at), v.cast_at)
        count[v.student_number] = count.get(v.student_number, 0) + 1
    total_pos = len(position_groups(ballot_candidates(db, e)))
    rows = db.scalars(select(User).where(User.role == "student").order_by(User.student_number)).all()
    return [{"student_number": u.student_number, "full_name": u.full_name, "program": u.program,
             "respondent_code": u.respondent_code, "has_voted": u.student_number in voted,
             "voted_at": voted[u.student_number].isoformat() if u.student_number in voted else None,
             "positions_voted": count.get(u.student_number, 0), "positions_total": total_pos} for u in rows]


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
    w.writerow(["student_number", "full_name", "program", "position", "candidate", "transaction_id", "cast_at"])
    for r in _audit_rows(db, get_election(db)):
        w.writerow([r["student_number"], r["full_name"], r["program"], r["position"], r["candidate_name"],
                    r["transaction_id"], r["cast_at"]])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=votera_votes.csv"})


@app.get("/admin/backup")
def backup(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """One JSON file with the election, candidates, results, votes, turnout and feedback. No passwords or OTP data."""
    e = get_election(db)
    cands = db.scalars(select(Candidate).where(Candidate.election_id == e.id)).all()
    audit(db, admin.student_number, "admin", "backup", "Backup exported")
    return {"exported_at": utcnow().isoformat(), "election": {"title": e.title, "status": e.status},
            "candidates": [{"id": c.id, "full_name": c.full_name, "program": c.program, "position": c.position,
                            "originality": c.originality_score, "achievements": c.achievements_score, "leadership": c.leadership_score,
                            "community": c.community_score, "credibility": c.credibility_score} for c in cands],
            "votes": _audit_rows(db, e), "turnout_by_program": turnout_by_program(admin, db),
            "feedback": feedback_summary(admin, db)}


@app.post("/admin/election/reset")
def reset_election(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Clears all votes and sets the election back to upcoming so the simulation can be rerun."""
    e = get_election(db)
    n = db.query(Vote).filter(Vote.election_id == e.id).delete()
    e.status = "upcoming"
    e.closes_at = None
    db.commit()
    audit(db, admin.student_number, "admin", "election_reset", f"{n} votes removed")
    ensure_sample_candidates(db)  # with no votes left, the sample candidates for every position can be added (once)
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
    groups = position_groups(db.scalars(select(Candidate).where(Candidate.election_id == e.id)).all())
    if not groups:
        raise HTTPException(409, "No candidates")
    voted = set(db.scalars(select(Vote.student_number).where(Vote.election_id == e.id)))
    pool = [u for u in db.scalars(select(User).where(User.role == "student").order_by(User.student_number))
            if u.student_number not in voted]
    random.shuffle(pool)
    added = 0
    for u in pool[:body.count]:
        for pname, group in groups:  # one random vote for every position
            db.add(Vote(election_id=e.id, candidate_id=random.choice(group).id, position=pname, student_number=u.student_number,
                        transaction_id=transaction_id(u.student_number, e.id, pname)))
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


# ---------------- Proof documents (certificates) ----------------
PROOF_CATEGORIES = ("achievements", "leadership", "community")
MAX_PROOFS_PER_CATEGORY = 6


def _proof_out(p: Proof, admin: bool = True) -> dict:
    d = {"id": p.id, "candidate_id": p.candidate_id, "category": p.category, "caption": p.caption, "status": p.status,
         "created_at": p.created_at.isoformat() + "Z" if p.created_at else None,
         "issuer": p.issuer or "", "issued_on": p.issued_on or "",
         "verified_at": p.verified_at.isoformat() + "Z" if p.verified_at and p.status == "verified" else None}
    if admin:   # which administrator checked it is shown to administrators only
        d["verified_by"] = p.verified_by
    return d


@app.get("/candidates/{candidate_id}/proofs")
def list_proofs(candidate_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Students see the verified documents; the administrator sees all of them (including rejected ones)."""
    q = select(Proof).where(Proof.candidate_id == candidate_id).order_by(Proof.category, Proof.id)
    if user.role != "admin":
        cand = db.get(Candidate, candidate_id)
        if not cand or not is_published(cand):
            return []
        q = q.where(Proof.status == "verified")
    return [_proof_out(p, user.role == "admin") for p in db.scalars(q)]


@app.get("/proofs/{proof_id}/image")
def get_proof_image(proof_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = db.get(Proof, proof_id)
    if not p or (user.role != "admin" and p.status != "verified"):
        raise HTTPException(404, "No such document")
    return Response(p.data, media_type=p.mime or "image/jpeg", headers={"Cache-Control": "private, max-age=3600"})


@app.post("/admin/candidates/{candidate_id}/proofs")
async def add_proof(candidate_id: int, request: Request, category: str = "achievements", caption: str = "",
                    issuer: str = "", issued_on: str = "", admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Body is the raw image bytes (JPEG or PNG, up to 3 MB). The app shrinks the picture before sending."""
    if category not in PROOF_CATEGORIES:
        raise HTTPException(422, "category must be achievements, leadership or community")
    c = db.get(Candidate, candidate_id)
    if not c:
        raise HTTPException(404, "Candidate not found")
    data = await request.body()
    if len(data) > 3_000_000:
        raise HTTPException(413, "Picture is too large (max 3 MB)")
    if data[:3] == b"\xff\xd8\xff":
        kind = "image/jpeg"
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        kind = "image/png"
    else:
        raise HTTPException(415, "Use a JPEG or PNG picture")
    n = db.scalar(select(func.count()).select_from(Proof).where(Proof.candidate_id == c.id, Proof.category == category))
    if n >= MAX_PROOFS_PER_CATEGORY:
        raise HTTPException(409, f"At most {MAX_PROOFS_PER_CATEGORY} documents for each category")
    clean = lambda t, n: re.sub(r"\s+", " ", t).strip()[:n]
    p = Proof(candidate_id=c.id, category=category, caption=clean(caption, 120), issuer=clean(issuer, 80) or None,
              issued_on=clean(issued_on, 20) or None, mime=kind, data=data, verified_by=admin.student_number, verified_at=utcnow())
    db.add(p)
    db.commit()
    audit(db, admin.student_number, "admin", "proof_added", f"{c.full_name}: {category}")
    notify("candidates")
    return _proof_out(p)


class ProofPatch(BaseModel):
    status: str | None = None
    caption: str | None = Field(default=None, max_length=120)
    issuer: str | None = Field(default=None, max_length=80)
    issued_on: str | None = Field(default=None, max_length=20)


@app.patch("/admin/proofs/{proof_id}")
def patch_proof(proof_id: int, body: ProofPatch, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    p = db.get(Proof, proof_id)
    if not p:
        raise HTTPException(404, "No such document")
    if body.status is not None:
        if body.status not in ("verified", "rejected"):
            raise HTTPException(422, "status must be verified or rejected")
        if body.status != p.status:
            p.verified_by, p.verified_at = admin.student_number, utcnow()
        p.status = body.status
    if body.caption is not None:
        p.caption = body.caption.strip()[:120]
    if body.issuer is not None:
        p.issuer = body.issuer.strip()[:80] or None
    if body.issued_on is not None:
        p.issued_on = body.issued_on.strip()[:20] or None
    db.commit()
    audit(db, admin.student_number, "admin", "proof_updated", f"#{p.id} {p.status}")
    notify("candidates")
    return _proof_out(p)


@app.get("/admin/proofs/summary")
def proofs_summary(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """For the checklist and the report: documents on file per candidate and which written claims have no verified document yet."""
    e = get_election(db)
    out = []
    for c in db.scalars(select(Candidate).where(Candidate.election_id == e.id).order_by(Candidate.id)):
        d = candidate_out(c, True)
        out.append({"candidate_id": c.id, "full_name": c.full_name, "position": c.position, "documents": d["proof_count"],
                    "missing": d["missing_proof"]})
    return {"candidates": out, "missing_total": sum(len(x["missing"]) for x in out)}


@app.delete("/admin/proofs/{proof_id}")
def delete_proof(proof_id: int, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    p = db.get(Proof, proof_id)
    if not p:
        raise HTTPException(404, "No such document")
    db.delete(p)
    db.commit()
    audit(db, admin.student_number, "admin", "proof_deleted", f"#{proof_id}")
    notify("candidates")
    return {"deleted": proof_id}


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



# ---------------- Admin: candidate draft/publish, voter profile, one-voter password reset, sessions ----------------
@app.put("/admin/candidates/{candidate_id}/published")
def set_published(candidate_id: int, body: PublishedIn, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Draft candidates are hidden from students (list, ballot, results); the administrator still sees them."""
    c = db.get(Candidate, candidate_id)
    if not c:
        raise HTTPException(404, "Candidate not found")
    if not body.published and db.scalar(select(func.count()).select_from(Vote).where(Vote.candidate_id == c.id)):
        raise HTTPException(409, "This candidate already has votes, so it cannot be turned back into a draft.")
    c.published = body.published
    db.commit()
    audit(db, admin.student_number, "admin", "candidate_published" if body.published else "candidate_draft", c.full_name)
    notify("candidates", "results")
    return candidate_out(c, True)


def _student_or_404(db: Session, student_number: str) -> User:
    u = db.scalar(select(User).where(User.student_number == student_number.strip().upper(), User.role == "student"))
    if not u:
        raise HTTPException(404, "Student not found")
    return u


ONLINE_MINUTES = 15


def _online(u: User) -> bool:
    if not u.last_seen:
        return False
    if u.tokens_valid_after and u.last_seen <= u.tokens_valid_after:
        return False
    return (now_naive() - u.last_seen).total_seconds() <= ONLINE_MINUTES * 60


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() + "Z" if d else None


@app.get("/admin/voters/{student_number}/profile")
def voter_profile(student_number: str, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Quick profile for the Admin > Voters tab: who the student is, whether they are online, and which positions they voted for."""
    u = _student_or_404(db, student_number)
    e = get_election(db)
    names = {c.id: c.full_name for c in db.scalars(select(Candidate).where(Candidate.election_id == e.id))}
    votes = db.scalars(select(Vote).where(Vote.election_id == e.id, Vote.student_number == u.student_number).order_by(Vote.cast_at)).all()
    total = len(position_groups(ballot_candidates(db, e)))
    return {"student_number": u.student_number, "full_name": u.full_name, "program": u.program, "respondent_code": u.respondent_code,
            "last_login": _iso(u.last_login), "last_seen": _iso(u.last_seen), "online": _online(u),
            "positions_voted": len(votes), "positions_total": total,
            "votes": [{"position": v.position or "", "candidate_name": names.get(v.candidate_id, "?"),
                       "transaction_id": v.transaction_id, "cast_at": _iso(v.cast_at)} for v in votes]}


@app.post("/admin/voters/{student_number}/reset-password")
def reset_one_password(student_number: str, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Creates a new random password for ONE student and ends that student's open sessions. The plain text is returned once
    (only the bcrypt hash is stored)."""
    u = _student_or_404(db, student_number)
    pw = secrets.token_urlsafe(6)
    u.password_hash = hash_password(pw, rounds=10)
    u.tokens_valid_after = now_naive()
    u.otp_pending = False
    clear_fails(u.student_number)
    db.commit()
    audit(db, admin.student_number, "admin", "password_reset", u.student_number)
    return {"student_number": u.student_number, "full_name": u.full_name, "password": pw}


@app.get("/admin/sessions")
def active_sessions(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Accounts seen in the last 15 minutes (newest first)."""
    since = now_naive() - timedelta(minutes=ONLINE_MINUTES)
    rows = [u for u in db.scalars(select(User).where(User.last_seen.is_not(None), User.last_seen >= since).order_by(User.last_seen.desc())) if _online(u)]
    return {"minutes": ONLINE_MINUTES, "sessions": [{"student_number": u.student_number, "full_name": u.full_name, "role": u.role, "program": u.program,
                                                       "last_login": _iso(u.last_login), "last_seen": _iso(u.last_seen)} for u in rows]}


@app.post("/admin/sessions/{student_number}/end")
def end_session(student_number: str, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Signs the account out everywhere: its tokens stop working at the next request."""
    u = db.scalar(select(User).where(User.student_number == student_number.strip().upper()))
    if not u:
        raise HTTPException(404, "Account not found")
    if u.id == admin.id:
        raise HTTPException(400, "You cannot end your own session here. Use Log out.")
    u.tokens_valid_after = now_naive()
    u.otp_pending = False
    db.commit()
    audit(db, admin.student_number, "admin", "session_ended", u.student_number)
    return {"ended": u.student_number}


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
            s2.add(Vote(election_id=1, candidate_id=1, position="President", student_number="S-1", transaction_id="t1"))
            s2.commit()
            s2.add(Vote(election_id=1, candidate_id=3, position="Vice President", student_number="S-1", transaction_id="t3"))
            s2.commit()  # a different position is allowed
            s2.add(Vote(election_id=1, candidate_id=2, position="President", student_number="S-1", transaction_id="t2"))
            try:
                s2.commit()
                return False, "A second vote by the same student for the same position was accepted"
            except IntegrityError:
                return True, "One vote per position: a second vote for the same position is refused by the database"
    check("Voting", "One student, one vote per position", t_onevote)

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