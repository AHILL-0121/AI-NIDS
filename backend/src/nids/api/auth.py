"""Single-admin authentication (audit SEC-01).

- First run: `POST /api/auth/setup` creates the one admin account; it refuses once one exists.
- Passwords are hashed with argon2id.
- Login creates a server-side session. The browser gets an HttpOnly, SameSite=Strict cookie with a
  random token; the database stores only the token's SHA-256.
- Every state-changing request must also send the session's CSRF token in `X-CSRF-Token`.
- Login attempts are rate-limited per client address.
"""

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select

from nids.api.errors import ApiError
from nids.store.db import Database
from nids.store.models import AuthSession, User, utcnow
from nids.store.repo import audit

COOKIE = "nids_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MIN_PASSWORD = 12

_hasher = PasswordHasher()  # argon2id with the library's recommended parameters


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class RateLimiter:
    """At most `limit` events per `window_s` seconds per key (client address)."""

    def __init__(self, limit: int, window_s: float) -> None:
        self.limit, self.window_s = limit, window_s
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] > self.window_s:
                events.popleft()
            if len(events) >= self.limit:
                retry = int(self.window_s - (now - events[0])) + 1
                raise ApiError(
                    429,
                    f"Too many attempts. Try again in {retry} s.",
                    details={"retry_after_s": retry},
                )
            events.append(now)


login_limiter = RateLimiter(limit=5, window_s=60)


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    csrf_token: str


def get_db(request: Request) -> Database:
    db: Database = request.app.state.db
    return db


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def resolve_session(db: Database, token: str | None, ttl_s: float) -> Principal | None:
    if not token:
        return None
    now = utcnow()
    with db.session() as s:
        session = s.get(AuthSession, _digest(token))
        if session is None or session.expires_at < now:
            return None
        user = s.get(User, session.user_id)
        if user is None:
            return None
        # Sliding expiry: an active session stays valid; an idle one expires after `ttl_s`.
        session.last_seen_at = now
        session.expires_at = now + ttl_s
        return Principal(user.id, user.username, session.csrf_token)


def require_user(request: Request, db: Database = Depends(get_db)) -> Principal:
    """Dependency for every protected route: a valid session, plus CSRF on writes."""
    ttl = request.app.state.settings.session_ttl_hours * 3600
    principal = resolve_session(db, request.cookies.get(COOKIE), ttl)
    if principal is None:
        raise ApiError(401, "Please sign in.")
    if request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not hmac.compare_digest(sent, principal.csrf_token):
            raise ApiError(403, "Missing or invalid CSRF token.", code="csrf")
    return principal


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256)


class SetupRequest(Credentials):
    password: str = Field(min_length=MIN_PASSWORD, max_length=256)


class AuthStatus(BaseModel):
    setup_required: bool
    authenticated: bool
    username: str | None = None
    csrf_token: str | None = None


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=MIN_PASSWORD, max_length=256)


router = APIRouter(prefix="/api/auth", tags=["auth"])


def _has_user(db: Database) -> bool:
    with db.session() as s:
        return bool(s.scalar(select(func.count()).select_from(User)))


def _start_session(request: Request, response: Response, db: Database, user: User) -> AuthStatus:
    settings = request.app.state.settings
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    now = utcnow()
    with db.session() as s:
        s.execute(delete(AuthSession).where(AuthSession.expires_at < now))
        s.add(
            AuthSession(
                token_hash=_digest(token),
                user_id=user.id,
                csrf_token=csrf,
                expires_at=now + settings.session_ttl_hours * 3600,
                client=_client(request)[:256],
            )
        )
        u = s.get(User, user.id)
        if u is not None:
            u.last_login_at = now
        audit(s, user.username, "auth.login", None, client=_client(request))
    response.set_cookie(
        COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=settings.secure_cookies,
        path="/",
        max_age=int(settings.session_ttl_hours * 3600),
    )
    return AuthStatus(
        setup_required=False, authenticated=True, username=user.username, csrf_token=csrf
    )


@router.get("/status")
def status(request: Request, db: Database = Depends(get_db)) -> AuthStatus:
    """Whether first-run setup is needed and whether this browser is signed in. Returns the CSRF
    token for the signed-in session (the UI keeps it in memory, not in storage)."""
    ttl = request.app.state.settings.session_ttl_hours * 3600
    principal = resolve_session(db, request.cookies.get(COOKIE), ttl)
    return AuthStatus(
        setup_required=not _has_user(db),
        authenticated=principal is not None,
        username=principal.username if principal else None,
        csrf_token=principal.csrf_token if principal else None,
    )


@router.post("/setup", status_code=201)
def setup(
    body: SetupRequest, request: Request, response: Response, db: Database = Depends(get_db)
) -> AuthStatus:
    """Create the admin account. Only possible while no account exists."""
    login_limiter.check(_client(request))
    if _has_user(db):
        raise ApiError(409, "Setup is already done. Sign in instead.")
    with db.session() as s:
        user = User(username=body.username, password_hash=_hasher.hash(body.password))
        s.add(user)
        s.flush()
        audit(s, body.username, "auth.setup", None)
    return _start_session(request, response, db, user)


@router.post("/login")
def login(
    body: Credentials, request: Request, response: Response, db: Database = Depends(get_db)
) -> AuthStatus:
    login_limiter.check(_client(request))
    with db.session() as s:
        user = s.scalars(select(User).where(User.username == body.username)).first()
        stored = user.password_hash if user else None
    try:
        if stored is None:
            _hasher.hash(body.password)  # same cost either way: don't reveal which usernames exist
            raise VerifyMismatchError
        _hasher.verify(stored, body.password)
    except (VerifyMismatchError, VerificationError) as exc:
        raise ApiError(401, "Wrong username or password.") from exc
    assert user is not None
    if _hasher.check_needs_rehash(stored):
        with db.session() as s:
            u = s.get(User, user.id)
            if u is not None:
                u.password_hash = _hasher.hash(body.password)
    return _start_session(request, response, db, user)


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    principal: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> None:
    token = request.cookies.get(COOKIE)
    with db.session() as s:
        if token:
            s.execute(delete(AuthSession).where(AuthSession.token_hash == _digest(token)))
        audit(s, principal.username, "auth.logout", None)
    response.delete_cookie(COOKIE, path="/")


@router.post("/password", status_code=204)
def change_password(
    body: PasswordChange,
    principal: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> None:
    """Change the password and sign out every other session."""
    with db.session() as s:
        user = s.get(User, principal.user_id)
        assert user is not None
        try:
            _hasher.verify(user.password_hash, body.current_password)
        except (VerifyMismatchError, VerificationError) as exc:
            raise ApiError(401, "The current password is wrong.") from exc
        user.password_hash = _hasher.hash(body.new_password)
        s.execute(
            delete(AuthSession).where(
                AuthSession.user_id == user.id, AuthSession.csrf_token != principal.csrf_token
            )
        )
        audit(s, principal.username, "auth.password_change", None)
