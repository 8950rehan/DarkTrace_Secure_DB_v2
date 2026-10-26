import os
import re
import uuid
from datetime import datetime, timezone
from typing import Literal

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

DATABASE_URL = os.getenv("DATABASE_URL", "")
if not DATABASE_URL:
    # App can be imported for docs/tests, but database endpoints fail closed.
    DATABASE_URL = ""

app = FastAPI(title="DarkTrace Secure Database API", version="2.0.0")
password_hasher = PasswordHasher()


def get_conn():
    if not DATABASE_URL:
        raise HTTPException(status_code=503, detail="Database is not configured")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=5, autocommit=False)


class UserCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: Literal["analyst", "supervisor", "auditor", "readonly"] = "analyst"

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str) -> str:
        if not (re.search(r"[a-z]", value) and re.search(r"[A-Z]", value) and re.search(r"\d", value)):
            raise ValueError("Password must include lowercase, uppercase, and a number")
        return value


class SourceCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=2, max_length=160)
    source_type: Literal["onion_site", "forum", "marketplace", "paste", "blog", "i2p_site"]
    address: str = Field(min_length=3, max_length=2048)
    authorization_id: uuid.UUID
    created_by: uuid.UUID

    @field_validator("address")
    @classmethod
    def address_sane(cls, value: str) -> str:
        if any(ord(c) < 32 for c in value):
            raise ValueError("Address contains control characters")
        return value


class CrawlCreate(BaseModel):
    source_id: uuid.UUID
    requested_by: uuid.UUID
    kind: Literal["scheduled", "incremental", "manual"] = "manual"
    intent_id: uuid.UUID


@app.get("/health")
def health():
    return {"status": "ok", "database_configured": bool(DATABASE_URL)}


@app.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate):
    user_id = uuid.uuid4()
    # Argon2id via argon2-cffi; plaintext password is never persisted or logged.
    hashed = password_hasher.hash(payload.password)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (usr_id, username, email, password_hash, role) "
                "VALUES (%s, %s, %s, %s, %s) RETURNING usr_id, username, email, role, status, created_at",
                (user_id, payload.username, str(payload.email).lower(), hashed, payload.role),
            )
            row = cur.fetchone()
            conn.commit()
            return row
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Username or email already exists")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Could not create user")


@app.post("/sources", status_code=status.HTTP_201_CREATED)
def create_source(payload: SourceCreate):
    try:
        with get_conn() as conn, conn.cursor() as cur:
            # Require current, valid authorization before registering a source.
            cur.execute(
                "SELECT 1 FROM authorizations WHERE authorization_id = %s AND status = 'active' "
                "AND valid_from <= now() AND valid_until > now()",
                (payload.authorization_id,),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=422, detail="Authorization is missing, inactive, or expired")
            cur.execute(
                "INSERT INTO source (name, source_type, address, authorization_id, created_by) "
                "VALUES (%s, %s, %s, %s, %s) "
                "RETURNING source_id, name, source_type, address, authorization_id, status, created_at",
                (payload.name, payload.source_type, payload.address, payload.authorization_id, payload.created_by),
            )
            row = cur.fetchone()
            conn.commit()
            return row
    except HTTPException:
        raise
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Source address already exists")
    except psycopg.errors.ForeignKeyViolation:
        raise HTTPException(status_code=422, detail="User or authorization reference does not exist")
    except Exception:
        raise HTTPException(status_code=500, detail="Could not create source")


@app.post("/crawl-jobs", status_code=status.HTTP_201_CREATED)
def create_crawl_job(payload: CrawlCreate):
    try:
        with get_conn() as conn, conn.cursor() as cur:
            # Only active sources with an active, unexpired authorization can be scheduled.
            cur.execute(
                "SELECT s.source_id FROM source s JOIN authorizations a ON a.authorization_id = s.authorization_id "
                "WHERE s.source_id = %s AND s.status = 'active' AND a.status = 'active' "
                "AND a.valid_from <= now() AND a.valid_until > now()",
                (payload.source_id,),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=422, detail="Source is inactive or has no valid authorization")
            cur.execute(
                "INSERT INTO crawl_job (intent_id, source_id, requested_by, kind) "
                "VALUES (%s, %s, %s, %s) RETURNING job_id, intent_id, source_id, requested_by, kind, state, created_at",
                (payload.intent_id, payload.source_id, payload.requested_by, payload.kind),
            )
            row = cur.fetchone()
            cur.execute(
                "INSERT INTO audit_log (actor_id, action, entity_type, entity_id, outcome, request_id) "
                "VALUES (%s, 'crawl_job.create', 'crawl_job', %s, 'success', %s)",
                (payload.requested_by, str(row["job_id"]), payload.intent_id),
            )
            conn.commit()
            return row
    except HTTPException:
        raise
    except psycopg.errors.ForeignKeyViolation:
        raise HTTPException(status_code=422, detail="User or source reference does not exist")
    except Exception:
        raise HTTPException(status_code=500, detail="Could not create crawl job")
