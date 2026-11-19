import hashlib
import re

from fastapi import Header, HTTPException


def owner_id(authorization: str | None = Header(None)) -> str:
    # Installation-scoped capability: clients generate and retain 32 random bytes.
    match = re.fullmatch(r"Bearer ([0-9a-f]{64})", authorization or "", re.IGNORECASE)
    if not match:
        raise HTTPException(401, "installation_token_required")
    return hashlib.sha256(bytes.fromhex(match[1])).hexdigest()
