# main.py
# Fireblocks -> Telegram webhook (FastAPI)
# - Filters out events involving "op@fundadmin.com"
# - Prettier Telegram formatting with emojis and HTML-safe text
# - Root (/) + /healthz + /fireblocks/webhook
# - Dual RSA verification (PKCS1v15 & PSS) + alt signature headers
# - Simple logs, optional debug

import base64
import json
import hmac
import logging

from fastapi import FastAPI, Request, Header, HTTPException
import httpx

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

app = FastAPI()
logging.basicConfig(level=logging.INFO)

# ─── Telegram bot credentials (yours) ─────────────────────────
TELEGRAM_BOT_TOKEN = "8267279608:AAEgyQ0bJO338F1Is34IXZ7unAl1khpt2qI"
TELEGRAM_CHAT_ID   = "54380770"

# ─── Fireblocks Stage public key (PEM) ────────────────────────
FIREBLOCKS_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw+fZuC+0vDYTf8fYnCN6
71iHg98lPHBmafmqZqb+TUexn9sH6qNIBZ5SgYFxFK6dYXIuJ5uoORzihREvZVZP
8DphdeKOMUrMr6b+Cchb2qS8qz8WS7xtyLU9GnBn6M5mWfjkjQr1jbilH15Zvcpz
ECC8aPUAy2EbHpnr10if2IHkIAWLYD+0khpCjpWtsfuX+LxqzlqQVW9xc6z7tshK
eCSEa6Oh8+ia7Zlu0b+2xmy2Arb6xGl+s+Rnof4lsq9tZS6f03huc+XVTmd6H2We
WxFMfGyDCX2akEg2aAvx7231/6S0vBFGiX0C+3GbXlieHDplLGoODHUt5hxbPJnK
IwIDAQAB
-----END PUBLIC KEY-----"""

# ─── Optional shared-secret (leave blank if unused) ───────────
FIREBLOCKS_WEBHOOK_SECRET = ""

# ─── Controls ─────────────────────────────────────────────────
ALLOW_UNVERIFIED = True      # flip to False once you’re done testing
DEBUG_TO_TELEGRAM = False    # set True to get small debug pings

# ─── Filters ──────────────────────────────────────────────────
# Any event whose From/To "name" contains something from this set will be suppressed.
FILTER_NAME_BLOCKLIST = {"op@fundadmin.com"}


# ─────────────────────────── Utils ────────────────────────────
def escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def fmt_amount(x):
    if x is None:
        return ""
    try:
        f = float(x)
        # format with thousands; trim trailing zeros
        s = f"{f:,.8f}".rstrip("0").rstrip(".")
        return s
    except Exception:
        return str(x)

def short(s, n=16):
    return (s or "")[:n]

def verify_rsa(raw_body: bytes, signature_b64: str, public_key_pem: str) -> bool:
    """Try RSA PKCS1v15 first, then RSA-PSS (both SHA-512)."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        signature = base64.b64decode(signature_b64)

        # PKCS1v15
        try:
            public_key.verify(signature, raw_body, padding.PKCS1v15(), hashes.SHA512())
            return True
        except InvalidSignature:
            pass

        # PSS
        try:
            public_key.verify(
                signature,
                raw_body,
                padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=hashes.SHA512().digest_size),
                hashes.SHA512(),
            )
            return True
        except InvalidSignature:
            return False
    except Exception:
        return False

def verify_shared_secret(provided_secret: str, configured_secret: str) -> bool:
    return hmac.compare_digest((provided_secret or "").strip(), (configured_secret or "").strip())

async def send_to_telegram(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"})

def pick_actor_fields(actor):
    """actor may be dict or string; return (type, name, id) all as strings (possibly empty)"""
    if isinstance(actor, dict):
        a_type = str(actor.get("type") or "")
        a_name = str(actor.get("name") or "")
        a_id   = str(actor.get("id") or "")
    else:
        # some payloads might give a string
        a_type = ""
        a_name = str(actor or "")
        a_id   = ""
    return a_type, a_name, a_id

def name_hit_blocklist(name: str) -> bool:
    n = (name or "").lower()
    for bad in FILTER_NAME_BLOCKLIST:
        if bad.lower() in n:
            return True
    return False

def coalesce_event(payload: dict) -> dict:
    """Normalize common Fireblocks payload shapes (top-level or nested under 'data'/'tx')."""
    if not isinstance(payload, dict):
        return {}

    evt_type = payload.get("type") or payload.get("eventType")
    status   = payload.get("status") or payload.get("txStatus")
    tx_id    = payload.get("id") or payload.get("transactionId")
    asset    = payload.get("assetId") or payload.get("asset") or payload.get("currency")
    amount   = payload.get("amount") or payload.get("value")
    src      = payload.get("source") or payload.get("from")
    dst      = payload.get("destination") or payload.get("to")
    tx_hash  = payload.get("txHash") or payload.get("networkTxHash")

    # Nested objects
    data = payload.get("data") or payload.get("tx") or {}
    if isinstance(data, dict):
        evt_type = evt_type or data.get("type")
        status   = status   or data.get("status")
        tx_id    = tx_id    or data.get("id") or data.get("transactionId")
        asset    = asset    or data.get("assetId") or data.get("asset") or data.get("currency")
        amount   = amount   or data.get("amount") or data.get("value")
        src      = src      or data.get("source") or data.get("from")
        dst      = dst      or data.get("destination") or data.get("to")
        tx_hash  = tx_hash  or data.get("txHash") or data.get("networkTxHash")

    # Actor details
    src_type, src_name, src_id = pick_actor_fields(src)
    dst_type, dst_name, dst_id = pick_actor_fields(dst)

    return {
        "evt_type": evt_type or "fireblocks_event",
        "status": status or "",
        "tx_id": short(str(tx_id)),
        "asset": str(asset or ""),
        "amount": amount,
        "src_type": src_type,
        "src_name": src_name,
        "src_id": short(src_id),
        "dst_type": dst_type,
        "dst_name": dst_name,
        "dst_id": short(dst_id),
        "tx_hash": short(str(tx_hash)) if tx_hash else "",
    }

def should_suppress(norm: dict) -> bool:
    """Filter: suppress if either side name hits the blocklist."""
    return name_hit_blocklist(norm.get("src_name", "")) or name_hit_blocklist(norm.get("dst_name", ""))

def status_emoji(status: str) -> str:
    s = (status or "").upper()
    if s in {"CONFIRMED", "COMPLETED", "SUCCESS"}:
        return "✅"
    if s in {"FAILED", "CANCELLED", "REJECTED"}:
        return "❌"
    if s in {"PENDING_SIGNATURE", "PENDING_AUTHORIZATION", "SUBMITTED", "QUEUED", "BROADCASTING"}:
        return "🕒"
    if s in {"CONFIRMING", "IN_BLOCK", "PENDING_3RD_PARTY"}:
        return "⏳"
    return "•"

def format_event(norm: dict) -> str:
    # Build clean actor strings
    def fmt_actor(a_type, a_name, a_id):
        parts = []
        if a_type: parts.append(a_type.replace("_", " ").title())
        if a_name: parts.append(f"{escape_html(a_name)}")
        if a_id:   parts.append(f"({escape_html(a_id)})")
        return " ".join(parts) if parts else "N/A"

    left  = fmt_actor(norm.get("src_type",""), norm.get("src_name",""), norm.get("src_id",""))
    right = fmt_actor(norm.get("dst_type",""), norm.get("dst_name",""), norm.get("dst_id",""))

    # Header
    evt = escape_html(norm.get("evt_type","fireblocks_event"))
    status = norm.get("status","")
    icon = status_emoji(status)
    status_txt = escape_html(status)

    # Body
    txline = f"Tx: <code>{escape_html(norm.get('tx_id',''))}</code>" if norm.get("tx_id") else ""
    asset = escape_html(norm.get("asset",""))
    amount = fmt_amount(norm.get("amount"))
    amline = f"{amount} {asset}".strip() if amount or asset else ""
    hashline = f"Hash: <code>{escape_html(norm.get('tx_hash',''))}</code>" if norm.get("tx_hash") else ""

    lines = [
        f"<b>{icon} Fireblocks</b>: {evt}",
        f"Status: <b>{status_txt}</b>" if status_txt else "",
        txline,
        f"Amount: {amline}" if amline else "",
        f"From: {left}",
        f"To: {right}",
        hashline,
    ]
    # remove empties, join
    return "\n".join([ln for ln in lines if ln])

# ─────────────────────────── Routes ───────────────────────────
@app.get("/")
async def root():
    return {
        "ok": True,
        "service": "Fireblocks → Telegram webhook",
        "health": "/healthz",
        "webhook": "/fireblocks/webhook",
        "verification": "skipped" if ALLOW_UNVERIFIED else "rsa/secret",
        "filters": list(FILTER_NAME_BLOCKLIST),
    }

@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.post("/fireblocks/webhook")
async def fireblocks_webhook(
    request: Request,
    fireblocks_signature: str | None = Header(default=None, convert_underscores=False),   # "Fireblocks-Signature"
    x_fireblocks_signature: str | None = Header(default=None, convert_underscores=False), # "X-Fireblocks-Signature"
    x_webhook_secret: str | None = Header(default=None, convert_underscores=False),       # "X-Webhook-Secret"
):
    raw = await request.body()

    # Verify
    verified = False
    signature_b64 = fireblocks_signature or x_fireblocks_signature

    if FIREBLOCKS_PUBLIC_KEY_PEM.strip() and signature_b64:
        verified = verify_rsa(raw, signature_b64, FIREBLOCKS_PUBLIC_KEY_PEM)

    if not verified and FIREBLOCKS_WEBHOOK_SECRET.strip():
        verified = verify_shared_secret(x_webhook_secret, FIREBLOCKS_WEBHOOK_SECRET)

    if not verified and not ALLOW_UNVERIFIED:
        logging.warning("Webhook rejected: signature/secret verification failed")
        raise HTTPException(status_code=401, detail="Signature/secret verification failed")

    # Parse
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        payload = {}

    norm = coalesce_event(payload)

    # Filter
    if should_suppress(norm):
        logging.info(f"Suppressed event (blocklist match): type={norm.get('evt_type')} tx={norm.get('tx_id')}")
        # still return 200 so Fireblocks doesn't retry
        return {"ok": True, "suppressed": True}

    # Notify
    msg = format_event(norm) if norm else "New Fireblocks event"
    logging.info(f"Webhook OK: type={norm.get('evt_type')} tx={norm.get('tx_id')} status={norm.get('status')}")
    if DEBUG_TO_TELEGRAM:
        await send_to_telegram(f"DEBUG: received {norm.get('evt_type')} / {norm.get('tx_id')}")
    await send_to_telegram(msg)
    return {"ok": True}
