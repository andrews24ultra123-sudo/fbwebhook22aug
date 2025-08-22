# main.py
# FastAPI webhook that receives Fireblocks events and forwards alerts to Telegram.

import base64, json, hmac
from fastapi import FastAPI, Request, Header, HTTPException
import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

app = FastAPI()

# ─── Telegram bot credentials ───────────────────────────────
TELEGRAM_BOT_TOKEN = "8267279608:AAEgyQ0bJO338F1Is34IXZ7unAl1khpt2qI"
TELEGRAM_CHAT_ID   = "54380770"

# ─── Fireblocks Stage public key (PEM format) ────────────────
FIREBLOCKS_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw+fZuC+0vDYTf8fYnCN6
71iHg98lPHBmafmqZqb+TUexn9sH6qNIBZ5SgYFxFK6dYXIuJ5uoORzihREvZVZP
8DphdeKOMUrMr6b+Cchb2qS8qz8WS7xtyLU9GnBn6M5mWfjkjQr1jbilH15Zvcpz
ECC8aPUAy2EbHpnr10if2IHkIAWLYD+0khpCjpWtsfuX+LxqzlqQVW9xc6z7tshK
eCSEa6Oh8+ia7Zlu0b+2xmy2Arb6xGl+s+Rnof4lsq9tZS6f03huc+XVTmd6H2We
WxFMfGyDCX2akEg2aAvx7231/6S0vBFGiX0C+3GbXlieHDplLGoODHUt5hxbPJnK
IwIDAQAB
-----END PUBLIC KEY-----"""

# ─── Shared secret (not needed if using signature) ───────────
FIREBLOCKS_WEBHOOK_SECRET = ""

# ─── Stage override ─────────────────────────────────────────
ALLOW_UNVERIFIED = False   # since we now validate with the public key


# ─────────────────────────── Helpers ─────────────────────────
def verify_rsa_signature(raw_body: bytes, signature_b64: str, public_key_pem: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            raw_body,
            padding.PKCS1v15(),
            hashes.SHA512()
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

def verify_shared_secret(provided_secret: str, configured_secret: str) -> bool:
    return hmac.compare_digest((provided_secret or "").strip(), (configured_secret or "").strip())

async def send_to_telegram(text: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"})

def format_event(payload: dict) -> str:
    evt_type = payload.get("type") or payload.get("eventType") or "fireblocks_event"
    tx_id = (payload.get("id") or payload.get("transactionId") or "")[:16]
    status = payload.get("status") or payload.get("txStatus") or ""
    asset = payload.get("assetId") or payload.get("asset") or payload.get("currency") or ""
    amount = payload.get("amount") or payload.get("value") or ""
    src = payload.get("source") or payload.get("from") or ""
    dst = payload.get("destination") or payload.get("to") or ""

    lines = [f"<b>Fireblocks:</b> {evt_type}"]
    if tx_id:   lines.append(f"Tx: <code>{tx_id}</code>")
    if status:  lines.append(f"Status: <b>{status}</b>")
    if asset:   lines.append(f"Asset: {asset}")
    if amount:  lines.append(f"Amount: {amount}")
    if src:     lines.append(f"From: {src}")
    if dst:     lines.append(f"To: {dst}")
    return "\n".join(lines)

# ─────────────────────────── Routes ──────────────────────────
@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.post("/fireblocks/webhook")
async def fireblocks_webhook(
    request: Request,
    fireblocks_signature: str | None = Header(default=None, convert_underscores=False),
    x_webhook_secret: str | None = Header(default=None, convert_underscores=False),
):
    raw = await request.body()

    # Verify RSA signature if header present
    verified = False
    if FIREBLOCKS_PUBLIC_KEY_PEM.strip() and fireblocks_signature:
        verified = verify_rsa_signature(raw, fireblocks_signature, FIREBLOCKS_PUBLIC_KEY_PEM)

    # Fallback: shared secret
    if not verified and FIREBLOCKS_WEBHOOK_SECRET.strip():
        verified = verify_shared_secret(x_webhook_secret, FIREBLOCKS_WEBHOOK_SECRET)

    if not verified and not ALLOW_UNVERIFIED:
        raise HTTPException(status_code=401, detail="Signature/secret verification failed")

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        payload = {}

    text = format_event(payload) if isinstance(payload, dict) else "New Fireblocks event"
    await send_to_telegram(text)
    return {"ok": True}
