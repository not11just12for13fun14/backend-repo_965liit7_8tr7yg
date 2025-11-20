import os
import hashlib
import base64
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Request, Response, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from itsdangerous import TimestampSigner, BadSignature
from dotenv import load_dotenv
from pymongo import ReturnDocument
from bson import ObjectId

from database import db
from schemas import SealCreate, SealMeta, OTPBody, NDAConfirm, TTL_VALUES

# Optional imports
try:
    import gridfs
except Exception:  # pragma: no cover
    gridfs = None

try:
    from argon2 import PasswordHasher
    ph = PasswordHasher()
except Exception:  # pragma: no cover
    ph = None

load_dotenv()

app = FastAPI(title="Cypheon Seal (Mongo Edition)", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Constants
MAX_FILES = 7
MAX_TOTAL = 250 * 1024 * 1024  # 250 MB
COOKIE_NDA = "cyp_nda"
COOKIE_OTP = "cyp_otp"
COOKIE_OWNER = "cyp_owner"
SIGN_SECRET = os.getenv("SIGN_SECRET", "dev-sign-secret-change")
signer = TimestampSigner(SIGN_SECRET)

# Helpers

def oid_str(oid: ObjectId | str) -> str:
    return str(oid)


def now_utc():
    return datetime.now(timezone.utc)


def ensure_collections():
    for name in ["seals", "seal_files", "seal_access", "audit_events"]:
        db[name].create_index("seal_id")
    db["seals"].create_index("expires_at")


ensure_collections()


class UploadResponse(BaseModel):
    file_id: str
    name: str
    size: int
    mime: str
    sha256_hex: str


@app.get("/")
def read_root():
    return {"message": "Cypheon Seal Backend Ready"}


@app.get("/test")
def test_database():
    return {
        "backend": "ok",
        "database": "ok" if db is not None else "missing",
        "collections": db.list_collection_names() if db is not None else [],
    }


@app.post("/upload", response_model=UploadResponse)
async def upload_file(
    request: Request,
    f: UploadFile = File(...),
    content_md5: Optional[str] = Form(None),
):
    if db is None:
        raise HTTPException(500, "Database not configured")
    if gridfs is None:
        raise HTTPException(500, "GridFS not available")

    # Read and stream into hash
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    total = 0
    chunks: List[bytes] = []
    while True:
        chunk = await f.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_TOTAL:
            raise HTTPException(413, "File too large (over total limit)")
        sha.update(chunk)
        md5.update(chunk)
        chunks.append(chunk)

    sha_hex = sha.hexdigest()
    computed_md5_b64 = base64.b64encode(md5.digest()).decode()
    if content_md5 and content_md5 != computed_md5_b64:
        raise HTTPException(400, "Content-MD5 mismatch")

    fs = gridfs.GridFS(db)
    file_id = fs.put(b"".join(chunks), filename=f.filename, contentType=f.content_type or "application/octet-stream", sha256=sha_hex, size=total)

    return UploadResponse(
        file_id=str(file_id),
        name=f.filename,
        size=total,
        mime=f.content_type or "application/octet-stream",
        sha256_hex=sha_hex,
    )


@app.post("/seal")
async def create_seal(resp: Response, payload: SealCreate, request: Request):
    if db is None:
        raise HTTPException(500, "Database not configured")

    if payload.ttl not in TTL_VALUES:
        raise HTTPException(400, "Invalid TTL")

    if len(payload.files) > MAX_FILES:
        raise HTTPException(400, "Too many files")

    total_bytes = sum(f.size for f in payload.files)
    if total_bytes > MAX_TOTAL:
        raise HTTPException(400, "Total size exceeds 250MB")

    otp_hash = None
    if payload.otp:
        if ph is None:
            raise HTTPException(500, "OTP hashing not available")
        otp_hash = ph.hash(payload.otp)

    created_at = now_utc()
    expires_at = created_at + timedelta(seconds=TTL_VALUES[payload.ttl])

    seal_doc = {
        "created_at": created_at,
        "expires_at": expires_at,
        "owner_id": None,
        "e2ee": payload.e2ee,
        "otp_hash": otp_hash,
        "nda_required": payload.nda,
        "geo_allowlist": payload.geo or None,
        "max_opens": payload.maxOpens,
        "single_use": payload.singleUse,
        "revoked_at": None,
        "message": payload.msg,
        "total_bytes": total_bytes,
    }

    res = db["seals"].insert_one(seal_doc)
    seal_id = str(res.inserted_id)

    # Files
    for f in payload.files:
        db["seal_files"].insert_one({
            "seal_id": seal_id,
            "name": f.name,
            "size": f.size,
            "mime": f.mime,
            "sha256_hex": f.sha256_hex,
            "gridfs_id": f.id,
        })

    db["seal_access"].insert_one({"seal_id": seal_id, "opens_count": 0, "last_open_at": None})

    # Set owner cookie
    owner_token = signer.sign(seal_id).decode()
    resp.set_cookie(COOKIE_OWNER, owner_token, httponly=True, samesite="lax")

    return {"id": seal_id}


@app.get("/seal/{seal_id}", response_model=SealMeta)
async def get_seal_meta(seal_id: str):
    s = db["seals"].find_one({"_id": ObjectId(seal_id)})
    if not s:
        raise HTTPException(404, "Not found")

    files = []
    for f in db["seal_files"].find({"seal_id": seal_id}):
        files.append({
            "id": f["gridfs_id"],
            "name": f["name"],
            "size": f["size"],
            "mime": f.get("mime", "application/octet-stream"),
            "sha256_hex": f["sha256_hex"],
        })

    meta = {
        "id": seal_id,
        "created_at": s["created_at"],
        "expires_at": s["expires_at"],
        "e2ee": s["e2ee"],
        "nda_required": s["nda_required"],
        "geo_allowlist": s.get("geo_allowlist"),
        "max_opens": s.get("max_opens"),
        "single_use": s.get("single_use", False),
        "revoked": s.get("revoked_at") is not None,
        "message": s.get("message"),
        "files": files,
    }
    return meta


@app.post("/seal/{seal_id}/nda")
async def accept_nda(seal_id: str, body: NDAConfirm, resp: Response):
    s = db["seals"].find_one({"_id": ObjectId(seal_id)})
    if not s:
        raise HTTPException(404, "Not found")
    if not body.accepted:
        raise HTTPException(400, "Must accept NDA")
    token = signer.sign(f"nda:{seal_id}").decode()
    resp.set_cookie(COOKIE_NDA, token, httponly=True, samesite="lax")
    return {"ok": True}


@app.post("/seal/{seal_id}/otp")
async def verify_otp(seal_id: str, body: OTPBody, resp: Response, request: Request):
    s = db["seals"].find_one({"_id": ObjectId(seal_id)})
    if not s:
        raise HTTPException(404, "Not found")
    if not s.get("otp_hash"):
        return {"ok": True}
    if ph is None:
        raise HTTPException(500, "OTP hashing not available")
    try:
        ph.verify(s["otp_hash"], body.code)
    except Exception:
        raise HTTPException(401, "Invalid code")
    token = signer.sign(f"otp:{seal_id}").decode()
    resp.set_cookie(COOKIE_OTP, token, httponly=True, samesite="lax")
    return {"ok": True}


@app.post("/seal/{seal_id}/revoke")
async def revoke(seal_id: str, request: Request, owner: Optional[str] = Cookie(default=None, alias=COOKIE_OWNER)):
    if not owner:
        raise HTTPException(401, "Owner cookie required")
    try:
        raw = signer.unsign(owner, max_age=60*60*24*7).decode()
        if raw != seal_id:
            raise HTTPException(403, "Not owner")
    except BadSignature:
        raise HTTPException(403, "Invalid owner token")
    updated = db["seals"].find_one_and_update(
        {"_id": ObjectId(seal_id)}, {"$set": {"revoked_at": now_utc()}}, return_document=ReturnDocument.AFTER
    )
    if not updated:
        raise HTTPException(404, "Not found")
    return {"ok": True}


def _check_gate(seal_id: str, nda_cookie: Optional[str], otp_cookie: Optional[str]):
    s = db["seals"].find_one({"_id": ObjectId(seal_id)})
    if not s:
        raise HTTPException(404, "Not found")
    if s.get("revoked_at"):
        raise HTTPException(403, "Revoked")
    if s["expires_at"] <= now_utc():
        raise HTTPException(410, "Expired")

    if s.get("nda_required"):
        if not nda_cookie:
            raise HTTPException(403, "NDA required")
        try:
            raw = signer.unsign(nda_cookie, max_age=60*60*24*7).decode()
            if raw != f"nda:{seal_id}":
                raise HTTPException(403, "NDA mismatch")
        except BadSignature:
            raise HTTPException(403, "Invalid NDA cookie")

    if s.get("otp_hash"):
        if not otp_cookie:
            raise HTTPException(401, "OTP required")
        try:
            raw = signer.unsign(otp_cookie, max_age=60*60*24).decode()
            if raw != f"otp:{seal_id}":
                raise HTTPException(403, "OTP mismatch")
        except BadSignature:
            raise HTTPException(403, "Invalid OTP cookie")

    # Access counters
    acc = db["seal_access"].find_one_and_update(
        {"seal_id": seal_id},
        {"$inc": {"opens_count": 1}, "$set": {"last_open_at": now_utc()}},
        return_document=ReturnDocument.AFTER,
    )
    if s.get("max_opens") and acc["opens_count"] > s["max_opens"]:
        raise HTTPException(403, "Max opens exceeded")

    return s


@app.get("/seal/{seal_id}/download")
async def download_link(
    seal_id: str,
    file: str,
    nda_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NDA),
    otp_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_OTP),
):
    s = _check_gate(seal_id, nda_cookie, otp_cookie)

    fdoc = db["seal_files"].find_one({"seal_id": seal_id, "gridfs_id": file})
    if not fdoc:
        raise HTTPException(404, "File not found")

    # Create signed download token valid for 5 minutes
    token = signer.sign(f"dl:{file}:{seal_id}").decode()
    return {"url": f"/download/{file}?t={token}"}


@app.get("/download/{file_id}")
async def download_file(file_id: str, t: str):
    if gridfs is None:
        raise HTTPException(500, "GridFS not available")
    try:
        raw = signer.unsign(t, max_age=300).decode()
        parts = raw.split(":")
        if len(parts) != 3 or parts[0] != "dl" or parts[1] != file_id:
            raise HTTPException(403, "Invalid token")
    except BadSignature:
        raise HTTPException(403, "Invalid token")

    fs = gridfs.GridFS(db)
    try:
        fobj = fs.get(ObjectId(file_id))
    except Exception:
        raise HTTPException(404, "Not found")

    def streamer():
        while True:
            chunk = fobj.read(1024 * 1024)
            if not chunk:
                break
            yield chunk

    media_type = getattr(fobj, "contentType", "application/octet-stream")
    headers = {"Content-Disposition": f"attachment; filename=\"{fobj.filename}\""}
    return StreamingResponse(streamer(), media_type=media_type, headers=headers)
