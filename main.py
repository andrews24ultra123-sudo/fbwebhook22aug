# main.py
# Fireblocks -> Telegram webhook (FastAPI)
# - Root route (/) so Railway health checks won't 404
# - Health route (/healthz)
# - Webhook route (/fireblocks/webhook)
# - Dual RSA verification (PKCS1v15 and PSS) + alt signature headers
# - Simple logs and optional Telegram debug pings

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

# ─── Telegram bot credentials (YOURS) ─────────────────────────
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
ALLOW_UNVERIFIED = True     # <<< set to False after testing to enforce signature checks
DEBUG_TO_TELEGRAM = False   # set to True to get tiny debug pings on every webhook hit


# ─────────────────────────── Helpers ──────────────────────────
def verify_rsa(raw_body: bytes, signature_b64: str, public_key_pem: str) -> bool:
    """Try RSA PKCS1v15 first, then RSA-PSS (both SHA-512)."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        signature = base64.b64decode(signature_b64)

        # Attempt PKCS1v15
        try:
            public_key.verify(signature, raw_body, padding.PKCS1v15(), hashes.SHA512())
            return True
        except InvalidSignature:
            pass

        # Attempt PSS
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

def coalesce_event(payload: dict) -> dict:
    """Normalize common Fireblocks payload shapes (top-level or nested under 'data'/'tx')."""
    if not isinstance(payload, dict):
        return {}

    # Prefer top-level keys
    evt_type = payload.get("type") or payload.get("eventType")
    status   = payload.get("status") or payload.get("txStatus")
    tx_id    = payload.get("id") or payload.get("transactionId")
    asset    = payload.get("assetId") or payload.get("asset") or payload.get("currency")
    amount   = payload.get("amount") or payload.get("value")
    src      = payload.get("source") or payload.get("from")
    dst      = payload.get("destination") or payload.get("to")

    # Check common nests
    data = payload.get("data") or payload.get("tx") or {}
    if isinstance(data, dict):
        evt_type = evt_type or data.get("type")
        status   = status   or data.get("status")
        tx_id    = tx_id    or data.get("id") or data.get("transactionId")
        asset    = asset    or data.get("assetId") or data.get("asset") or data.get("currency")
        amount   = amount   or data.get("amount") or data.get("value")
        src      = src      or data.get("source") or data.get("from")
        dst      = dst      or data.get("destination") or data.get("to")

    return {
        "evt_type": evt_type or "fireblocks_event",
        "status": status or "",
        "tx_id": (tx_id or "")[:16],
        "asset": asset or "",
        "amount": amount or "",
        "src": src or "",
        "dst": dst or "",
    }

def format_event(norm: dict) -> str:
    lines = [f"<b>Fireblocks:</b> {norm.get('evt_type','fireblocks_event')}"]
    if norm.get("tx_id"):   lines.append(f"Tx: <code>{norm['tx_id']}</code>")
    if norm.get("status"):  lines.append(f"Status: <b>{norm['status']}</b>")
    if norm.get("asset"):   lines.append(f"Asset: {norm['asset']}")
    if norm.get("amount"):  lines.append(f"Amount: {norm['amount']}")
    if norm.get("src"):     lines.append(f"From: {norm['src']}")
    if norm.get("dst"):     lines.append(f"To: {norm['dst']}")
    return "\n".join(lines)


# ─────────────────────────── Routes ───────────────────────────
@app.get("/")
async def root():
    return {
        "ok": True,
        "service": "Fireblocks → Telegram webhook",
        "health": "/healthz",
        "webhook": "/fireblocks/webhook",
        "verification": "skipped" if ALLOW_UNVERIFIED else "rsa/secret"
    }

@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.post("/fireblocks/webhook")
async def fireblocks_webhook(
    request: Request,
    # Accept either header variant
    fireblocks_signature: str | None = Header(default=None, convert_underscores=False),   # "Fireblocks-Signature"
    x_fireblocks_signature: str | None = Header(default=None, convert_underscores=False), # "X-Fireblocks-Signature"
    x_webhook_secret: str | None = Header(default=None, convert_underscores=False),       # "X-Webhook-Secret" (if used)
):
    raw = await request.body()

    # Signature verification
    verified = False
    signature_b64 = fireblocks_signature or x_fireblocks_signature

    # 1) RSA verification (preferred)
    if FIREBLOCKS_PUBLIC_KEY_PEM.strip() and signature_b64:
        verified = verify_rsa(raw, signature_b64, FIREBLOCKS_PUBLIC_KEY_PEM)

    # 2) Shared-secret fallback
    if not verified and FIREBLOCKS_WEBHOOK_SECRET.strip():
        verified = verify_shared_secret(x_webhook_secret, FIREBLOCKS_WEBHOOK_SECRET)

    # 3) Allow bypass in stage for quick sanity
    if not verified and not ALLOW_UNVERIFIED:
        logging.warning("Webhook rejected: signature/secret verification failed")
        raise HTTPException(status_code=401, detail="Signature/secret verification failed")

    # Parse and format
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        payload = {}

    norm = coalesce_event(payload)
    msg = format_event(norm) if norm else "New Fireblocks event"

    logging.info(f"Webhook OK: type={norm.get('evt_type')} tx={norm.get('tx_id')} status={norm.get('status')}")
    if DEBUG_TO_TELEGRAM:
        await send_to_telegram(f"DEBUG: received {norm.get('evt_type')} / {norm.get('tx_id')}")

    await send_to_telegram(msg)
    return {"ok": True}
