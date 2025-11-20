"""
Database Schemas for Cypheon Seal (adapted MongoDB version)

Each Pydantic model corresponds to a collection (lowercased class name).
"""
from __future__ import annotations
from pydantic import BaseModel, Field, AwareDatetime, constr, conlist, conint
from typing import List, Optional
from datetime import datetime

TTL_VALUES = {"5m": 300, "30m": 1800, "1h": 3600, "1d": 86400, "7d": 604800}

class SealFile(BaseModel):
    id: str = Field(..., description="GridFS file id (as string)")
    name: str
    size: int
    mime: str
    sha256_hex: str

class SealCreate(BaseModel):
    files: conlist(SealFile, min_length=1, max_length=7)
    msg: Optional[constr(max_length=2000)] = None
    ttl: constr(to_lower=True) = Field(..., description="One of 5m,30m,1h,1d,7d")
    otp: Optional[constr(min_length=4, max_length=32)] = None
    nda: bool = True
    geo: Optional[List[constr(min_length=2, max_length=2)]] = None
    maxOpens: Optional[conint(ge=1, le=1000)] = None
    singleUse: bool = False
    e2ee: bool = True

class SealMeta(BaseModel):
    id: str
    created_at: AwareDatetime
    expires_at: AwareDatetime
    e2ee: bool
    nda_required: bool
    geo_allowlist: Optional[List[str]] = None
    max_opens: Optional[int] = None
    single_use: bool
    revoked: bool = False
    message: Optional[str] = None
    files: List[SealFile]

class OTPBody(BaseModel):
    code: constr(min_length=4, max_length=32)

class NDAConfirm(BaseModel):
    accepted: bool = True

class DownloadQuery(BaseModel):
    file: str

class AuditEvent(BaseModel):
    id: str
    seal_id: str
    ts: AwareDatetime
    event: str
    ip_hash: str
    ua_hash: str
    country: Optional[constr(min_length=2, max_length=2)] = None
    sig: Optional[str] = None
