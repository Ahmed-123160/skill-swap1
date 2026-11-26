"""
backend.py  -  Skill Swap API  (FastAPI + MySQL)

التشغيل:
    pip install -r requirements.txt
    python backend.py
الـ API بيشتغل على  http://127.0.0.1:8004   والتوثيق التلقائي على  /docs

إعدادات (كلها اختيارية، بتتغير من متغيرات البيئة):
    DB_HOST (127.0.0.1)  DB_PORT (3306)  DB_USER (root)  DB_PASSWORD ("")  DB_NAME (skill_swap_v2)
    SKILLSWAP_SECRET   مفتاح توقيع الـ JWT (غيّره قبل أي نشر حقيقي)
    MAX_VIDEO_MB (50)   UPLOAD_DIR
"""
import os
import re
import uuid
import base64
import hashlib
import hmac
import json
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

import bcrypt
import mysql.connector

# Load PyJWT when available, and use a small standard-library fallback so the
# API can still run when the optional jwt package has not been installed.
try:
    jwt = __import__("jwt")
except ImportError:
    class PyJWTError(Exception):
        pass

    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _b64url_decode(data: str) -> bytes:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))

    class _JWTFallback:
        PyJWTError = PyJWTError

        @staticmethod
        def encode(payload: dict, key: str, algorithm: str = "HS256") -> str:
            if algorithm != "HS256":
                raise PyJWTError("Only HS256 is supported")
            header = _b64url_encode(json.dumps({"alg": algorithm, "typ": "JWT"}, separators=(",", ":")).encode())
            body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            signing_input = f"{header}.{body}"
            signature = hmac.new(key.encode(), signing_input.encode(), hashlib.sha256).digest()
            return f"{signing_input}.{_b64url_encode(signature)}"

        @staticmethod
        def decode(token: str, key: str, algorithms=None) -> dict:
            try:
                header_part, payload_part, signature_part = token.split(".")
                header = json.loads(_b64url_decode(header_part))
                if algorithms and header.get("alg") not in algorithms:
                    raise PyJWTError("Invalid token algorithm")
                if header.get("alg") != "HS256":
                    raise PyJWTError("Invalid token algorithm")
                signing_input = f"{header_part}.{payload_part}"
                expected = hmac.new(key.encode(), signing_input.encode(), hashlib.sha256).digest()
                actual = _b64url_decode(signature_part)
                if not hmac.compare_digest(expected, actual):
                    raise PyJWTError("Invalid token signature")
                payload = json.loads(_b64url_decode(payload_part))
                if not isinstance(payload, dict):
                    raise PyJWTError("Invalid token payload")
                exp = payload.get("exp")
                if exp is not None and time.time() >= float(exp):
                    raise PyJWTError("Token has expired")
                return payload
            except (ValueError, KeyError, json.JSONDecodeError, base64.binascii.Error) as exc:
                raise PyJWTError("Invalid token") from exc

    jwt = _JWTFallback()

from fastapi import (Depends, FastAPI, File, Form, HTTPException, Request,
                     UploadFile)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from mysql.connector import errorcode, pooling
from mysql.connector.errors import PoolError
from pydantic import BaseModel, Field

# =====================================================================
# 1) الإعدادات
# =====================================================================
DB_CONFIG = dict(
    host=os.getenv("DB_HOST", "127.0.0.1"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASSWORD", ""),
    database=os.getenv("DB_NAME", "skill_swap_v2"),
    charset="utf8mb4",
    use_pure=True,
)

SECRET_KEY = os.getenv("SKILLSWAP_SECRET", "dev-secret-change-me-before-deploying")
JWT_ALGORITHM = "HS256"
TOKEN_LIFETIME_HOURS = 24 * 7

UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR",
                            Path(__file__).resolve().parent / "uploads" / "videos"))
MAX_VIDEO_BYTES = int(os.getenv("MAX_VIDEO_MB", "50")) * 1024 * 1024
ALLOWED_VIDEO_TYPES = {".mp4": "video/mp4", ".webm": "video/webm"}
MAX_VIDEOS_PER_USER = 5

pool: Optional[pooling.MySQLConnectionPool] = None


# =====================================================================
# 2) الاتصال بالداتا بيز (connection pool + cursor جديد لكل طلب)
# =====================================================================
@contextmanager
def db_cursor():
    """بيجيب اتصال من الـ pool وcursor خاص بالطلب ده بس.
    لو حصل أي خطأ بيعمل rollback، ولو نجح بيعمل commit، وفي الآخر بيرجّع الاتصال للـ pool."""
    conn = pool.get_connection()
    cur = conn.cursor(dictionary=True)
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def q_all(sql, params=()):
    with db_cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def q_one(sql, params=()):
    with db_cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def q_exec(sql, params=()):
    """تنفيذ أمر كتابة وإرجاع (lastrowid, rowcount)."""
    with db_cursor() as cur:
        cur.execute(sql, params)
        return cur.lastrowid, cur.rowcount


def scalar(sql, params=()):
    row = q_one(sql, params)
    return list(row.values())[0] if row else None


def is_duplicate(err: mysql.connector.Error) -> bool:
    return getattr(err, "errno", None) == errorcode.ER_DUP_ENTRY


def like_pattern(text: str) -> str:
    """بيهرّب % و _ عشان اليوزر ميعملش pattern بإيده."""
    text = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{text}%"


def in_placeholders(values) -> str:
    return ",".join(["%s"] * len(values))


# =====================================================================
# 3) الباسورد والـ JWT
# =====================================================================
DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt()).decode()


def password_problem(pw: str) -> Optional[str]:
    """نفس قواعد صفحة التسجيل. بترجّع نص الخطأ أو None."""
    if len(pw.encode()) > 72:
        return "Password is too long (max 72 bytes)"
    if len(pw) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", pw):
        return "Password must contain an uppercase letter (A-Z)"
    if not re.search(r"[a-z]", pw):
        return "Password must contain a lowercase letter (a-z)"
    if not re.search(r"\d", pw):
        return "Password must contain a number (0-9)"
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "Password must contain a special character"
    return None


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_password(pw: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), stored_hash.encode())
    except ValueError:
        return False


def create_token(user_id: int) -> str:
    payload = {"sub": str(user_id),
               "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_LIFETIME_HOURS)}
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def user_from_token(token: str):
    """بيرجّع صف اليوزر من الداتا بيز لو التوكن سليم واليوزر مفعّل، غير كده None.
    الدور (role) بيتقري من الداتا بيز كل مرة، مش من التوكن."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        return None
    row = q_one("SELECT id, name, email, location, role, is_active FROM users WHERE id = %s",
                (user_id,))
    if not row or not row["is_active"]:
        return None
    return row


bearer = HTTPBearer(auto_error=False)


def current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    if not creds:
        raise HTTPException(401, "Login required")
    user = user_from_token(creds.credentials)
    if not user:
        raise HTTPException(401, "Session expired, please login again")
    return user


def admin_user(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admins only")
    return user


def public_user(row) -> dict:
    return {"id": row["id"], "name": row["name"], "email": row["email"],
            "location": row["location"], "role": row["role"]}


# =====================================================================
# 4) نماذج الإدخال (Pydantic)
# =====================================================================
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(max_length=255)
    password: str = Field(max_length=128)
    location: Optional[str] = Field(default="", max_length=100)


class LoginIn(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=128)


class ProfileIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    location: Optional[str] = Field(default="", max_length=100)


class MySkillIn(BaseModel):
    skill_id: int
    skill_type: Literal["teach", "learn"]


class SwapRequestIn(BaseModel):
    receiver_id: int
    skill_wanted_id: int
    skill_offered_id: Optional[int] = None
    message: Optional[str] = Field(default=None, max_length=500)


class RespondIn(BaseModel):
    action: Literal["accept", "reject"]


class ScheduleIn(BaseModel):
    scheduled_at: datetime


class ReviewIn(BaseModel):
    rating: int = Field(ge=1, le=5)
    comment: Optional[str] = Field(default=None, max_length=1000)


class ReportIn(BaseModel):
    reason: Literal["inappropriate", "spam", "misleading", "copyright", "other"]
    details: Optional[str] = Field(default=None, max_length=500)


class VideoReviewIn(BaseModel):
    action: Literal["approve", "reject"]
    reason: Optional[str] = Field(default=None, max_length=255)


class ReportHandleIn(BaseModel):
    action: Literal["resolve", "dismiss"]
    remove_video: bool = False


class ActiveIn(BaseModel):
    is_active: bool


class CategoryIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)


class SkillIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    category_id: int


class MessageIn(BaseModel):
    to_user: int
    message: str = Field(min_length=1, max_length=2000)


# =====================================================================
# 5) التطبيق والـ middleware
# =====================================================================
@asynccontextmanager
async def lifespan(_app: FastAPI):
    global pool
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    try:
        pool = pooling.MySQLConnectionPool(pool_name="skillswap", pool_size=8,
                                           pool_reset_session=True, **DB_CONFIG)
        print(f"[OK] Connected to MySQL  {DB_CONFIG['host']}:{DB_CONFIG['port']}"
              f"/{DB_CONFIG['database']}")
    except mysql.connector.Error as err:
        raise SystemExit(
            f"\n[ERROR] Cannot connect to MySQL ({err}).\n"
            f"  - تأكد إن MySQL شغال في XAMPP\n"
            f"  - تأكد من البورت (DB_PORT) واسم القاعدة (DB_NAME={DB_CONFIG['database']})\n")
    yield


app = FastAPI(title="Skill Swap API", lifespan=lifespan)


@app.middleware("http")
async def limit_upload_size(request: Request, call_next):
    """بيرفض رفع الفيديو الكبير من الـ header قبل ما نستقبله."""
    if request.method == "POST" and request.url.path == "/api/videos":
        length = request.headers.get("content-length", "")
        if length.isdigit() and int(length) > MAX_VIDEO_BYTES + 1_000_000:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Video is too large (max {MAX_VIDEO_BYTES // 1024 // 1024} MB)"})
    return await call_next(request)


# مضاف بعد الـ middleware اللي فوق، فبيبقى الأخير تنفيذًا من برّه
# التوكن بيتبعت في الـ header (مش cookie) فمش محتاجين allow_credentials
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(null|https?://(localhost|127\.0\.0\.1)(:\d+)?)$",
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, exc: RequestValidationError):
    """بيحوّل أخطاء التحقق لرسالة نصية واحدة، عشان الفرونت يعرضها مباشرة."""
    first = exc.errors()[0]
    field = ".".join(str(p) for p in first.get("loc", ()) if p not in ("body", "query", "path", "form"))
    message = first.get("msg", "Invalid input")
    return JSONResponse(status_code=422,
                        content={"detail": f"{field}: {message}" if field else message})


@app.exception_handler(mysql.connector.Error)
async def database_error_handler(_request: Request, exc: mysql.connector.Error):
    print(f"[DB ERROR] {exc}")
    if isinstance(exc, PoolError):
        return JSONResponse(status_code=503, content={"detail": "Server is busy, try again"})
    return JSONResponse(status_code=500, content={"detail": "Database error"})


@app.get("/api/health")
def health():
    return {"ok": True}


# =====================================================================
# 6) الحساب: تسجيل / دخول / بروفايلي
# =====================================================================
@app.post("/api/register", status_code=201)
def register(data: RegisterIn):
    email = data.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Invalid email address")
    problem = password_problem(data.password)
    if problem:
        raise HTTPException(400, problem)
    try:
        user_id, _ = q_exec(
            "INSERT INTO users (name, email, password_hash, location) VALUES (%s, %s, %s, %s)",
            (data.name.strip(), email, hash_password(data.password), (data.location or "").strip() or None))
    except mysql.connector.IntegrityError as err:
        if is_duplicate(err):
            raise HTTPException(400, "Email already exists")
        raise
    return {"success": True, "message": "Account created successfully", "user_id": user_id}


@app.post("/api/login")
def login(data: LoginIn):
    row = q_one("SELECT id, name, email, location, role, is_active, password_hash "
                "FROM users WHERE email = %s", (data.email.strip().lower(),))
    # بنعمل فحص باسورد حتى لو الإيميل غلط عشان الوقت ميكشفش إيه الإيميلات الموجودة
    ok = verify_password(data.password, row["password_hash"] if row else DUMMY_HASH)
    if not row or not ok:
        raise HTTPException(401, "Invalid email or password")
    if not row["is_active"]:
        raise HTTPException(403, "This account is disabled")
    return {"success": True, "token": create_token(row["id"]), "user": public_user(row)}


@app.get("/api/me")
def get_me(user=Depends(current_user)):
    return {"user": public_user(user)}


@app.put("/api/me")
def update_me(data: ProfileIn, user=Depends(current_user)):
    q_exec("UPDATE users SET name = %s, location = %s WHERE id = %s",
           (data.name.strip(), (data.location or "").strip() or None, user["id"]))
    row = q_one("SELECT id, name, email, location, role FROM users WHERE id = %s", (user["id"],))
    return {"success": True, "user": public_user(row)}


# =====================================================================
# 7) المهارات (الكتالوج + مهاراتي)
# =====================================================================
@app.get("/api/skills")
def list_skills():
    """كل المهارات المتاحة مع تصنيفها (للقوائم المنسدلة)."""
    rows = q_all("SELECT s.id, s.name, c.id AS category_id, c.name AS category "
                 "FROM skills s JOIN categories c ON c.id = s.category_id "
                 "ORDER BY c.name, s.name")
    return {"skills": rows}


@app.get("/api/my/skills")
def my_skills(user=Depends(current_user)):
    rows = q_all("SELECT s.id AS skill_id, s.name, c.name AS category, us.skill_type "
                 "FROM user_skills us JOIN skills s ON s.id = us.skill_id "
                 "JOIN categories c ON c.id = s.category_id "
                 "WHERE us.user_id = %s ORDER BY us.skill_type, s.name", (user["id"],))
    return {"skills": rows}


@app.post("/api/my/skills", status_code=201)
def add_my_skill(data: MySkillIn, user=Depends(current_user)):
    if not q_one("SELECT id FROM skills WHERE id = %s", (data.skill_id,)):
        raise HTTPException(404, "Skill not found")
    other = "learn" if data.skill_type == "teach" else "teach"
    if q_one("SELECT 1 FROM user_skills WHERE user_id = %s AND skill_id = %s AND skill_type = %s",
             (user["id"], data.skill_id, other)):
        raise HTTPException(400, f"You already listed this skill under '{other}'")
    try:
        q_exec("INSERT INTO user_skills (user_id, skill_id, skill_type) VALUES (%s, %s, %s)",
               (user["id"], data.skill_id, data.skill_type))
    except mysql.connector.IntegrityError as err:
        if is_duplicate(err):
            raise HTTPException(409, "Skill already added")
        raise
    return {"success": True}


@app.delete("/api/my/skills/{skill_id}/{skill_type}")
def remove_my_skill(skill_id: int, skill_type: Literal["teach", "learn"], user=Depends(current_user)):
    _, count = q_exec("DELETE FROM user_skills WHERE user_id = %s AND skill_id = %s AND skill_type = %s",
                      (user["id"], skill_id, skill_type))
    if not count:
        raise HTTPException(404, "Skill not found in your list")
    return {"success": True}


# =====================================================================
# 8) البحث والمطابقة والبروفايل العام
# =====================================================================
def attach_skills(rows):
    """بيضيف قائمة المهارات لكل يوزر باستعلام واحد (بدل استعلام لكل يوزر)."""
    for row in rows:
        row["skills"] = []
    if not rows:
        return rows
    by_id = {row["id"]: row for row in rows}
    skills = q_all(
        f"SELECT us.user_id, s.id AS skill_id, s.name, us.skill_type "
        f"FROM user_skills us JOIN skills s ON s.id = us.skill_id "
        f"WHERE us.user_id IN ({in_placeholders(by_id)}) ORDER BY us.skill_type, s.name",
        tuple(by_id))
    for skill in skills:
        by_id[skill.pop("user_id")]["skills"].append(skill)
    return rows


@app.get("/api/users")
def search_users(q: str = "", skill_id: Optional[int] = None,
                 skill_type: Optional[Literal["teach", "learn"]] = None,
                 user=Depends(current_user)):
    """بحث بالاسم أو اسم المهارة، وممكن فلتر بمهارة معينة (ومعاها teach/learn)."""
    sql = ("SELECT u.id, u.name, u.location, st.avg_rating, st.reviews_count, st.completed_sessions "
           "FROM users u LEFT JOIN user_stats st ON st.user_id = u.id "
           "WHERE u.is_active = 1 AND u.role = 'user' AND u.id <> %s")
    params = [user["id"]]
    q = q.strip()
    if q:
        pattern = like_pattern(q)
        sql += (" AND (u.name LIKE %s OR EXISTS (SELECT 1 FROM user_skills us "
                "JOIN skills s ON s.id = us.skill_id WHERE us.user_id = u.id AND s.name LIKE %s))")
        params += [pattern, pattern]
    if skill_id is not None:
        sql += " AND EXISTS (SELECT 1 FROM user_skills f WHERE f.user_id = u.id AND f.skill_id = %s"
        params.append(skill_id)
        if skill_type:
            sql += " AND f.skill_type = %s"
            params.append(skill_type)
        sql += ")"
    sql += " ORDER BY st.completed_sessions DESC, st.avg_rating DESC, u.name LIMIT 60"
    return {"users": attach_skills(q_all(sql, tuple(params)))}


@app.get("/api/matches")
def my_matches(user=Depends(current_user)):
    """مقترحات ليا: ناس بتعلّم اللي عايز أتعلمه، ويفضّل لو هما كمان عايزين يتعلموا اللي بعلّمه."""
    me = user["id"]
    rows = q_all(
        "SELECT * FROM ("
        " SELECT u.id, u.name, u.location,"
        "  (SELECT COUNT(*) FROM user_skills t JOIN user_skills m"
        "     ON m.skill_id = t.skill_id AND m.skill_type = 'learn' AND m.user_id = %s"
        "    WHERE t.user_id = u.id AND t.skill_type = 'teach') AS they_teach_me,"
        "  (SELECT COUNT(*) FROM user_skills l JOIN user_skills m"
        "     ON m.skill_id = l.skill_id AND m.skill_type = 'teach' AND m.user_id = %s"
        "    WHERE l.user_id = u.id AND l.skill_type = 'learn') AS i_teach_them"
        " FROM users u WHERE u.is_active = 1 AND u.role = 'user' AND u.id <> %s) x "
        "WHERE they_teach_me > 0 "
        "ORDER BY (they_teach_me + i_teach_them) DESC, i_teach_them DESC, name LIMIT 20",
        (me, me, me))
    for row in rows:
        row["mutual"] = row["i_teach_them"] > 0
    return {"matches": attach_skills(rows)}


@app.get("/api/users/{user_id}")
def get_profile(user_id: int, _user=Depends(current_user)):
    """بروفايل عام: من غير الإيميل."""
    row = q_one("SELECT u.id, u.name, u.location, u.created_at, st.avg_rating, st.reviews_count, "
                "st.completed_sessions FROM users u LEFT JOIN user_stats st ON st.user_id = u.id "
                "WHERE u.id = %s AND u.is_active = 1 AND u.role = 'user'", (user_id,))
    if not row:
        raise HTTPException(404, "User not found")
    attach_skills([row])
    row["videos"] = q_all(
        "SELECT v.id, v.title, v.description, v.skill_id, sk.name AS skill_name, v.uploaded_at "
        "FROM videos v LEFT JOIN skills sk ON sk.id = v.skill_id "
        "WHERE v.user_id = %s AND v.status = 'approved' ORDER BY v.uploaded_at DESC", (user_id,))
    row["reviews"] = q_all(
        "SELECT rv.id, rv.rating, rv.comment, rv.created_at, l.name AS reviewer_name, "
        "sk.name AS skill_name FROM reviews rv JOIN sessions s ON s.id = rv.session_id "
        "JOIN users l ON l.id = s.learner_id JOIN skills sk ON sk.id = s.skill_id "
        "WHERE s.teacher_id = %s ORDER BY rv.created_at DESC LIMIT 20", (user_id,))
    return row


# =====================================================================
# 9) طلبات التبادل
# =====================================================================
@app.post("/api/requests", status_code=201)
def create_request(data: SwapRequestIn, user=Depends(current_user)):
    me = user["id"]
    if data.receiver_id == me:
        raise HTTPException(400, "You cannot send a request to yourself")
    if not q_one("SELECT id FROM users WHERE id = %s AND is_active = 1 AND role = 'user'",
                 (data.receiver_id,)):
        raise HTTPException(404, "User not found")
    if not q_one("SELECT 1 FROM user_skills WHERE user_id = %s AND skill_id = %s AND skill_type = 'teach'",
                 (data.receiver_id, data.skill_wanted_id)):
        raise HTTPException(400, "This user does not teach the requested skill")
    if data.skill_offered_id is not None and not q_one(
            "SELECT 1 FROM user_skills WHERE user_id = %s AND skill_id = %s AND skill_type = 'teach'",
            (me, data.skill_offered_id)):
        raise HTTPException(400, "The skill you offer must be in your 'teach' list")
    if q_one("SELECT id FROM swap_requests WHERE requester_id = %s AND receiver_id = %s "
             "AND skill_wanted_id = %s AND status = 'pending'",
             (me, data.receiver_id, data.skill_wanted_id)):
        raise HTTPException(409, "You already have a pending request for this skill")
    request_id, _ = q_exec(
        "INSERT INTO swap_requests (requester_id, receiver_id, skill_wanted_id, skill_offered_id, message) "
        "VALUES (%s, %s, %s, %s, %s)",
        (me, data.receiver_id, data.skill_wanted_id, data.skill_offered_id,
         (data.message or "").strip() or None))
    return {"success": True, "request_id": request_id}


@app.get("/api/requests")
def list_requests(box: Literal["incoming", "outgoing"] = "incoming", user=Depends(current_user)):
    column = "r.receiver_id" if box == "incoming" else "r.requester_id"
    rows = q_all(
        "SELECT r.id, r.status, r.message, r.created_at, r.responded_at, "
        "r.requester_id, ru.name AS requester_name, r.receiver_id, vu.name AS receiver_name, "
        "r.skill_wanted_id, sw.name AS skill_wanted, r.skill_offered_id, so.name AS skill_offered "
        "FROM swap_requests r JOIN users ru ON ru.id = r.requester_id "
        "JOIN users vu ON vu.id = r.receiver_id JOIN skills sw ON sw.id = r.skill_wanted_id "
        "LEFT JOIN skills so ON so.id = r.skill_offered_id "
        f"WHERE {column} = %s ORDER BY (r.status = 'pending') DESC, r.created_at DESC LIMIT 100",
        (user["id"],))
    return {"requests": rows}


@app.post("/api/requests/{request_id}/respond")
def respond_to_request(request_id: int, data: RespondIn, user=Depends(current_user)):
    """المستقبِل بيقبل أو يرفض. القبول بيعمل جلسة (أو جلستين لو في مهارة معروضة) في نفس المعاملة."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM swap_requests WHERE id = %s FOR UPDATE", (request_id,))
        req = cur.fetchone()
        if not req:
            raise HTTPException(404, "Request not found")
        if req["receiver_id"] != user["id"]:
            raise HTTPException(403, "Only the receiver can respond")
        if req["status"] != "pending":
            raise HTTPException(409, f"Request is already {req['status']}")
        new_status = "accepted" if data.action == "accept" else "rejected"
        cur.execute("UPDATE swap_requests SET status = %s, responded_at = NOW() WHERE id = %s",
                    (new_status, request_id))
        sessions_created = 0
        if data.action == "accept":
            cur.execute("INSERT INTO sessions (request_id, teacher_id, learner_id, skill_id) "
                        "VALUES (%s, %s, %s, %s)",
                        (request_id, req["receiver_id"], req["requester_id"], req["skill_wanted_id"]))
            sessions_created = 1
            if req["skill_offered_id"]:
                cur.execute("INSERT INTO sessions (request_id, teacher_id, learner_id, skill_id) "
                            "VALUES (%s, %s, %s, %s)",
                            (request_id, req["requester_id"], req["receiver_id"], req["skill_offered_id"]))
                sessions_created = 2
    return {"success": True, "status": new_status, "sessions_created": sessions_created}


@app.post("/api/requests/{request_id}/cancel")
def cancel_request(request_id: int, user=Depends(current_user)):
    _, count = q_exec("UPDATE swap_requests SET status = 'cancelled', responded_at = NOW() "
                      "WHERE id = %s AND requester_id = %s AND status = 'pending'",
                      (request_id, user["id"]))
    if not count:
        raise HTTPException(404, "No pending request of yours with this id")
    return {"success": True}


# =====================================================================
# 10) الجلسات والتقييم
# =====================================================================
def load_my_session(session_id: int, user_id: int):
    row = q_one("SELECT * FROM sessions WHERE id = %s", (session_id,))
    if not row or user_id not in (row["teacher_id"], row["learner_id"]):
        raise HTTPException(404, "Session not found")
    return row


@app.get("/api/sessions")
def list_sessions(user=Depends(current_user)):
    me = user["id"]
    rows = q_all(
        "SELECT s.id, s.request_id, s.status, s.scheduled_at, s.completed_at, s.created_at, "
        "s.skill_id, sk.name AS skill_name, s.teacher_id, t.name AS teacher_name, "
        "s.learner_id, l.name AS learner_name, rv.rating AS review_rating, rv.comment AS review_comment "
        "FROM sessions s JOIN users t ON t.id = s.teacher_id JOIN users l ON l.id = s.learner_id "
        "JOIN skills sk ON sk.id = s.skill_id LEFT JOIN reviews rv ON rv.session_id = s.id "
        "WHERE s.teacher_id = %s OR s.learner_id = %s ORDER BY s.created_at DESC LIMIT 100",
        (me, me))
    for row in rows:
        row["my_role"] = "teacher" if row["teacher_id"] == me else "learner"
        row["can_complete"] = row["my_role"] == "learner" and row["status"] == "scheduled"
        row["can_review"] = (row["my_role"] == "learner" and row["status"] == "completed"
                             and row["review_rating"] is None)
    return {"sessions": rows}


@app.post("/api/sessions/{session_id}/schedule")
def schedule_session(session_id: int, data: ScheduleIn, user=Depends(current_user)):
    session = load_my_session(session_id, user["id"])
    if session["status"] != "scheduled":
        raise HTTPException(409, f"Session is already {session['status']}")
    when = data.scheduled_at.replace(tzinfo=None)
    if when < datetime.now():
        raise HTTPException(400, "Choose a time in the future")
    q_exec("UPDATE sessions SET scheduled_at = %s WHERE id = %s", (when, session_id))
    return {"success": True}


@app.post("/api/sessions/{session_id}/complete")
def complete_session(session_id: int, user=Depends(current_user)):
    """المتعلّم هو اللي يأكد إن الجلسة تمت (عشان التقييمات تبقى موثوقة)."""
    session = load_my_session(session_id, user["id"])
    if session["learner_id"] != user["id"]:
        raise HTTPException(403, "Only the learner can mark the session as completed")
    _, count = q_exec("UPDATE sessions SET status = 'completed', completed_at = NOW() "
                      "WHERE id = %s AND status = 'scheduled'", (session_id,))
    if not count:
        raise HTTPException(409, f"Session is already {session['status']}")
    return {"success": True}


@app.post("/api/sessions/{session_id}/cancel")
def cancel_session(session_id: int, user=Depends(current_user)):
    load_my_session(session_id, user["id"])
    _, count = q_exec("UPDATE sessions SET status = 'cancelled' WHERE id = %s AND status = 'scheduled'",
                      (session_id,))
    if not count:
        raise HTTPException(409, "Only scheduled sessions can be cancelled")
    return {"success": True}


@app.post("/api/sessions/{session_id}/review", status_code=201)
def review_session(session_id: int, data: ReviewIn, user=Depends(current_user)):
    session = load_my_session(session_id, user["id"])
    if session["learner_id"] != user["id"]:
        raise HTTPException(403, "Only the learner can review the teacher")
    if session["status"] != "completed":
        raise HTTPException(400, "You can review only completed sessions")
    try:
        review_id, _ = q_exec("INSERT INTO reviews (session_id, rating, comment) VALUES (%s, %s, %s)",
                              (session_id, data.rating, (data.comment or "").strip() or None))
    except mysql.connector.IntegrityError as err:
        if is_duplicate(err):
            raise HTTPException(409, "You already reviewed this session")
        raise
    return {"success": True, "review_id": review_id}


# =====================================================================
# 11) الفيديوهات (رفع مباشر + مراجعة الأدمن + بلاغات)
# =====================================================================
def looks_like_video(ext: str, head: bytes) -> bool:
    """فحص أول بايتات الملف، عشان محدش يرفع ملف تاني بامتداد mp4."""
    if ext == ".mp4":
        return len(head) >= 12 and head[4:8] == b"ftyp"
    if ext == ".webm":
        return head[:4] == b"\x1a\x45\xdf\xa3"
    return False


def delete_video_file(file_name: str):
    try:
        (UPLOAD_DIR / file_name).unlink(missing_ok=True)
    except OSError:
        pass


@app.post("/api/videos", status_code=201)
def upload_video(title: str = Form(..., min_length=3, max_length=150),
                 description: str = Form("", max_length=1000),
                 skill_id: Optional[str] = Form(None),
                 file: UploadFile = File(...),
                 user=Depends(current_user)):
    """رفع فيديو تعريفي. بيتخزن كملف في uploads/videos والمسار بس في الداتا بيز،
    وبيفضل pending لحد ما الأدمن يوافق عليه."""
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_VIDEO_TYPES or file.content_type != ALLOWED_VIDEO_TYPES[ext]:
        raise HTTPException(400, "Only .mp4 and .webm videos are allowed")

    skill = None
    if skill_id not in (None, ""):
        if not str(skill_id).isdigit() or not q_one("SELECT id FROM skills WHERE id = %s", (int(skill_id),)):
            raise HTTPException(400, "Unknown skill")
        skill = int(skill_id)

    if scalar("SELECT COUNT(*) FROM videos WHERE user_id = %s AND status <> 'rejected'",
              (user["id"],)) >= MAX_VIDEOS_PER_USER:
        raise HTTPException(400, f"You can have at most {MAX_VIDEOS_PER_USER} videos. Delete one first")

    dest = UPLOAD_DIR / f"{uuid.uuid4().hex}{ext}"
    size = 0
    try:
        with open(dest, "wb") as out:
            head = file.file.read(16)
            if not looks_like_video(ext, head):
                raise HTTPException(400, "The file is not a valid video")
            out.write(head)
            size = len(head)
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_VIDEO_BYTES:
                    raise HTTPException(413, f"Video is too large (max {MAX_VIDEO_BYTES // 1024 // 1024} MB)")
                out.write(chunk)
        video_id, _ = q_exec(
            "INSERT INTO videos (user_id, skill_id, title, description, file_path, file_size_bytes) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (user["id"], skill, title.strip(), description.strip() or None, dest.name, size))
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    return {"success": True, "video_id": video_id, "status": "pending"}


@app.get("/api/videos/mine")
def my_videos(user=Depends(current_user)):
    rows = q_all("SELECT v.id, v.title, v.description, v.status, v.rejection_reason, v.uploaded_at, "
                 "v.file_size_bytes, v.skill_id, sk.name AS skill_name "
                 "FROM videos v LEFT JOIN skills sk ON sk.id = v.skill_id "
                 "WHERE v.user_id = %s ORDER BY v.uploaded_at DESC", (user["id"],))
    return {"videos": rows}


@app.get("/api/videos/{video_id}/file")
def stream_video(video_id: int, token: Optional[str] = None):
    """الفيديو المعتمد متاح للكل. غير المعتمد بيفتحه صاحبه أو الأدمن بس، عن طريق ?token=
    (لأن وسم <video> مينفعش يبعت Authorization header)."""
    video = q_one("SELECT user_id, file_path, status FROM videos WHERE id = %s", (video_id,))
    if not video:
        raise HTTPException(404, "Video not found")
    if video["status"] != "approved":
        viewer = user_from_token(token) if token else None
        if not viewer or (viewer["id"] != video["user_id"] and viewer["role"] != "admin"):
            raise HTTPException(404, "Video not found")
    path = UPLOAD_DIR / video["file_path"]
    if not path.is_file():
        raise HTTPException(404, "Video file is missing")
    return FileResponse(path, media_type=ALLOWED_VIDEO_TYPES.get(path.suffix.lower(), "application/octet-stream"))


@app.delete("/api/videos/{video_id}")
def delete_video(video_id: int, user=Depends(current_user)):
    video = q_one("SELECT user_id, file_path FROM videos WHERE id = %s", (video_id,))
    if not video or (video["user_id"] != user["id"] and user["role"] != "admin"):
        raise HTTPException(404, "Video not found")
    q_exec("DELETE FROM videos WHERE id = %s", (video_id,))
    delete_video_file(video["file_path"])
    return {"success": True}


@app.post("/api/videos/{video_id}/report", status_code=201)
def report_video(video_id: int, data: ReportIn, user=Depends(current_user)):
    video = q_one("SELECT user_id, status FROM videos WHERE id = %s", (video_id,))
    if not video or video["status"] != "approved":
        raise HTTPException(404, "Video not found")
    if video["user_id"] == user["id"]:
        raise HTTPException(400, "You cannot report your own video")
    try:
        q_exec("INSERT INTO reports (video_id, reporter_id, reason, details) VALUES (%s, %s, %s, %s)",
               (video_id, user["id"], data.reason, (data.details or "").strip() or None))
    except mysql.connector.IntegrityError as err:
        if is_duplicate(err):
            raise HTTPException(409, "You already reported this video")
        raise
    return {"success": True}


# =====================================================================
# 12) الأدمن
# =====================================================================
@app.get("/api/admin/stats")
def admin_stats(_admin=Depends(admin_user)):
    def counts(table):
        return {r["status"]: r["n"] for r in q_all(f"SELECT status, COUNT(*) AS n FROM {table} GROUP BY status")}

    return {
        "users": scalar("SELECT COUNT(*) FROM users WHERE role = 'user'"),
        "active_users": scalar("SELECT COUNT(*) FROM users WHERE role = 'user' AND is_active = 1"),
        "skills": scalar("SELECT COUNT(*) FROM skills"),
        "requests": counts("swap_requests"),
        "sessions": counts("sessions"),
        "videos": counts("videos"),
        "open_reports": scalar("SELECT COUNT(*) FROM reports WHERE status = 'open'"),
        "top_requested_skills": q_all(
            "SELECT sk.name, COUNT(*) AS requests FROM swap_requests r "
            "JOIN skills sk ON sk.id = r.skill_wanted_id GROUP BY sk.id, sk.name "
            "ORDER BY requests DESC, sk.name LIMIT 5"),
        "top_teachers": q_all(
            "SELECT u.id, u.name, st.avg_rating, st.reviews_count, st.completed_sessions "
            "FROM user_stats st JOIN users u ON u.id = st.user_id WHERE st.reviews_count > 0 "
            "ORDER BY st.avg_rating DESC, st.reviews_count DESC LIMIT 5"),
    }


@app.get("/api/admin/videos")
def admin_list_videos(status: Literal["pending", "approved", "rejected"] = "pending",
                      _admin=Depends(admin_user)):
    rows = q_all("SELECT v.id, v.title, v.description, v.status, v.rejection_reason, v.uploaded_at, "
                 "v.file_size_bytes, v.user_id, u.name AS owner_name, sk.name AS skill_name "
                 "FROM videos v JOIN users u ON u.id = v.user_id "
                 "LEFT JOIN skills sk ON sk.id = v.skill_id "
                 "WHERE v.status = %s ORDER BY v.uploaded_at", (status,))
    return {"videos": rows}


@app.post("/api/admin/videos/{video_id}/review")
def admin_review_video(video_id: int, data: VideoReviewIn, admin=Depends(admin_user)):
    new_status = "approved" if data.action == "approve" else "rejected"
    reason = (data.reason or "").strip() or None
    if new_status == "rejected" and not reason:
        raise HTTPException(400, "Please write a rejection reason")
    _, count = q_exec("UPDATE videos SET status = %s, rejection_reason = %s, reviewed_by = %s, "
                      "reviewed_at = NOW() WHERE id = %s",
                      (new_status, reason if new_status == "rejected" else None, admin["id"], video_id))
    if not count:
        raise HTTPException(404, "Video not found")
    return {"success": True, "status": new_status}


@app.get("/api/admin/reports")
def admin_list_reports(status: Literal["open", "resolved", "dismissed"] = "open",
                       _admin=Depends(admin_user)):
    rows = q_all("SELECT rp.id, rp.reason, rp.details, rp.status, rp.created_at, rp.video_id, "
                 "v.title AS video_title, v.status AS video_status, rp.reporter_id, "
                 "ru.name AS reporter_name, v.user_id AS owner_id, ou.name AS owner_name "
                 "FROM reports rp JOIN videos v ON v.id = rp.video_id "
                 "JOIN users ru ON ru.id = rp.reporter_id JOIN users ou ON ou.id = v.user_id "
                 "WHERE rp.status = %s ORDER BY rp.created_at DESC LIMIT 100", (status,))
    return {"reports": rows}


@app.post("/api/admin/reports/{report_id}/handle")
def admin_handle_report(report_id: int, data: ReportHandleIn, admin=Depends(admin_user)):
    with db_cursor() as cur:
        cur.execute("SELECT video_id, status FROM reports WHERE id = %s FOR UPDATE", (report_id,))
        report = cur.fetchone()
        if not report:
            raise HTTPException(404, "Report not found")
        if report["status"] != "open":
            raise HTTPException(409, f"Report is already {report['status']}")
        new_status = "resolved" if data.action == "resolve" else "dismissed"
        cur.execute("UPDATE reports SET status = %s, handled_by = %s, handled_at = NOW() WHERE id = %s",
                    (new_status, admin["id"], report_id))
        if data.action == "resolve" and data.remove_video:
            cur.execute("UPDATE videos SET status = 'rejected', rejection_reason = 'Removed after a report', "
                        "reviewed_by = %s, reviewed_at = NOW() WHERE id = %s",
                        (admin["id"], report["video_id"]))
            cur.execute("UPDATE reports SET status = 'resolved', handled_by = %s, handled_at = NOW() "
                        "WHERE video_id = %s AND status = 'open'", (admin["id"], report["video_id"]))
    return {"success": True, "status": new_status}


@app.get("/api/admin/users")
def admin_list_users(_admin=Depends(admin_user)):
    rows = q_all("SELECT u.id, u.name, u.email, u.location, u.role, u.is_active, u.created_at, "
                 "st.completed_sessions, st.avg_rating FROM users u "
                 "LEFT JOIN user_stats st ON st.user_id = u.id ORDER BY u.created_at DESC LIMIT 200")
    return {"users": rows}


@app.post("/api/admin/users/{user_id}/active")
def admin_set_user_active(user_id: int, data: ActiveIn, admin=Depends(admin_user)):
    if user_id == admin["id"]:
        raise HTTPException(400, "You cannot disable your own account")
    target = q_one("SELECT role FROM users WHERE id = %s", (user_id,))
    if not target:
        raise HTTPException(404, "User not found")
    if target["role"] == "admin":
        raise HTTPException(400, "You cannot disable another admin")
    q_exec("UPDATE users SET is_active = %s WHERE id = %s", (int(data.is_active), user_id))
    return {"success": True}


@app.post("/api/admin/categories", status_code=201)
def admin_add_category(data: CategoryIn, _admin=Depends(admin_user)):
    try:
        category_id, _ = q_exec("INSERT INTO categories (name) VALUES (%s)", (data.name.strip(),))
    except mysql.connector.IntegrityError as err:
        if is_duplicate(err):
            raise HTTPException(409, "Category already exists")
        raise
    return {"success": True, "category_id": category_id}


@app.post("/api/admin/skills", status_code=201)
def admin_add_skill(data: SkillIn, _admin=Depends(admin_user)):
    if not q_one("SELECT id FROM categories WHERE id = %s", (data.category_id,)):
        raise HTTPException(404, "Category not found")
    try:
        skill_id, _ = q_exec("INSERT INTO skills (category_id, name) VALUES (%s, %s)",
                             (data.category_id, data.name.strip()))
    except mysql.connector.IntegrityError as err:
        if is_duplicate(err):
            raise HTTPException(409, "Skill already exists")
        raise
    return {"success": True, "skill_id": skill_id}


# =====================================================================
# 13) الرسائل
# =====================================================================
MESSAGE_FIELDS = "id, from_user, to_user, message, is_read, created_at"


@app.get("/api/messages/unread-count")
def unread_count(user=Depends(current_user)):
    return {"unread": scalar("SELECT COUNT(*) FROM messages WHERE to_user = %s AND is_read = 0",
                             (user["id"],))}


@app.get("/api/conversations")
def list_conversations(user=Depends(current_user)):
    """قائمة المحادثات: آخر رسالة مع كل شخص + عدد غير المقروء، باستعلامين بس."""
    me = user["id"]
    rows = q_all(
        "SELECT m.id, m.from_user, m.to_user, m.message AS last_message, m.created_at AS last_time, "
        "p.id AS partner_id, p.name AS partner_name "
        "FROM messages m JOIN (SELECT MAX(id) AS mid FROM messages "
        "  WHERE from_user = %s OR to_user = %s "
        "  GROUP BY LEAST(from_user, to_user), GREATEST(from_user, to_user)) x ON x.mid = m.id "
        "JOIN users p ON p.id = IF(m.from_user = %s, m.to_user, m.from_user) "
        "ORDER BY m.id DESC", (me, me, me))
    unread = {r["from_user"]: r["n"] for r in q_all(
        "SELECT from_user, COUNT(*) AS n FROM messages WHERE to_user = %s AND is_read = 0 "
        "GROUP BY from_user", (me,))}
    for row in rows:
        row["unread"] = unread.get(row["partner_id"], 0)
        row["last_from_me"] = row["from_user"] == me
        del row["from_user"], row["to_user"], row["id"]
    return {"conversations": rows}


@app.get("/api/messages/{other_id}")
def get_thread(other_id: int, after_id: int = 0, user=Depends(current_user)):
    """رسائل المحادثة. after_id بيخلّي الـ polling يجيب الجديد بس. (مبيعلّمش مقروء)"""
    me = user["id"]
    rows = q_all(
        f"SELECT {MESSAGE_FIELDS} FROM messages "
        "WHERE id > %s AND ((from_user = %s AND to_user = %s) OR (from_user = %s AND to_user = %s)) "
        "ORDER BY id DESC LIMIT 200", (after_id, me, other_id, other_id, me))
    rows.reverse()
    return {"messages": rows}


@app.post("/api/messages/{other_id}/read")
def mark_thread_read(other_id: int, user=Depends(current_user)):
    q_exec("UPDATE messages SET is_read = 1 WHERE from_user = %s AND to_user = %s AND is_read = 0",
           (other_id, user["id"]))
    return {"success": True}


@app.post("/api/messages", status_code=201)
def send_message(data: MessageIn, user=Depends(current_user)):
    if data.to_user == user["id"]:
        raise HTTPException(400, "You cannot message yourself")
    if not q_one("SELECT id FROM users WHERE id = %s AND is_active = 1", (data.to_user,)):
        raise HTTPException(404, "User not found")
    text = data.message.strip()
    if not text:
        raise HTTPException(400, "Message is empty")
    message_id, _ = q_exec("INSERT INTO messages (from_user, to_user, message) VALUES (%s, %s, %s)",
                           (user["id"], data.to_user, text))
    return {"success": True, "message_id": message_id}


# =====================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8004)
