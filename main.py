# main.py
# Fireblocks -> Telegram webhook (FastAPI)
# - Custom alerts:
#   * ETH_TEST5 + To=Internal Wallet N/A (id starts with bac86fcc-...) => QCDT MINT/BURN message
#   * QCDT_B75VRLGX_QIBD + To=One Time Address N/A => QCDT WITHDRAWAL message (with amount)
# - Filters out events with "op@fundadmin.com"
# - Uses FULL Fireblocks Transaction ID
# - Root + health endpoints included
# - Dual RSA verification (PKCS1v15 & PSS) + alt signature headers

import base64, json, hmac, logging, os
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
FILTER_NAME_BLOCKLIST = {"op@fundadmin.com"}  # suppress by From/To name
QCDT_INTERNAL_WALLET_ID = "bac86fcc-c41e-404f-8efb-acb1a90a0a3c"   # full id you mentioned

# ─────────────────────────── Utils ────────────────────────────
def escape_html(s: str) -> str:
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;") if isinstance(s,str) else str(s)

def fmt_amount(x):
    if x is None:
        return ""
    try:
        f = float(str(x))
        s = f"{f:,.8f}".rstrip("0").rstrip(".")
        return s
    except Exception:
        # if it's not a number, just return as-is
        return str(x)

def verify_rsa(raw_body: bytes, signature_b64: str, public_key_pem: str) -> bool:
    """Try RSA PKCS1v15 first, then RSA-PSS (both SHA-512)."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
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

def verify_shared_secret(provided, configured):
    return hmac.compare_digest((provided or "").strip(), (configured or "").strip())

async def send_to_telegram(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient(timeout=10) as c:
        await c.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"})

def pick_actor_fields(actor):
    """
    actor can be a dict or a string; return normalized:
    (type, name, id, full_id_if_present)
    """
    if isinstance(actor, dict):
        a_type = str(actor.get("type") or "")
        a_name = str(actor.get("name") or "")
        a_id   = str(actor.get("id") or "")
        return a_type, a_name, a_id, a_id  # for now id==full_id if present
    # sometimes it's just a string
    a = str(actor or "")
    return "", a, "", ""

def coalesce_event(payload: dict) -> dict:
    """
    Normalize common Fireblocks payload shapes (top-level or nested under 'data'/'tx').
    Returns keys we need for routing & formatting.
    """
    if not isinstance(payload, dict):
        return {}

    # try top-level
    evt_type = payload.get("type") or payload.get("eventType")
    status   = payload.get("status") or payload.get("txStatus")
    tx_id    = payload.get("id") or payload.get("transactionId")  # FULL FB tx id
    asset    = payload.get("assetId") or payload.get("asset") or payload.get("currency")
    amount   = payload.get("amount") or payload.get("value")
    src      = payload.get("source") or payload.get("from")
    dst      = payload.get("destination") or payload.get("to")

    # look in common nests
    data = payload.get("data") or payload.get("tx") or {}
    if isinstance(data, dict):
        evt_type = evt_type or data.get("type")
        status   = status   or data.get("status")
        tx_id    = tx_id    or data.get("id") or data.get("transactionId")
        asset    = asset    or data.get("assetId") or data.get("asset") or data.get("currency")
        amount   = amount   or data.get("amount") or data.get("value")
        src      = src      or data.get("source") or data.get("from")
        dst      = dst      or data.get("destination") or data.get("to")

    src_type, src_name, src_id, src_id_full = pick_actor_fields(src)
    dst_type, dst_name, dst_id, dst_id_full = pick_actor_fields(dst)

    return {
        "evt_type": evt_type or "fireblocks_event",
        "status": status or "",
        "tx_id": str(tx_id or ""),              # FULL FB tx id
        "asset": str(asset or ""),
        "amount": amount,
        "src_type": src_type, "src_name": src_name, "src_id": src_id, "src_id_full": src_id_full,
        "dst_type": dst_type, "dst_name": dst_name, "dst_id": dst_id, "dst_id_full": dst_id_full,
    }

def should_suppress_by_name(norm: dict) -> bool:
    for bad in FILTER_NAME_BLOCKLIST:
        if bad.lower() in (norm.get("src_name","").lower()) or bad.lower() in (norm.get("dst_name","").lower()):
            return True
    return False

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
        "rules": [
            "ETH_TEST5 + To=Internal Wallet N/A (id starts bac86fcc-...) -> Mint/Burn alert",
            "QCDT_B75VRLGX_QIBD + To=One Time Address N/A -> Withdrawal alert"
        ]
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

    # Blocklist by name
    if should_suppress_by_name(norm):
        logging.info(f"Suppressed (name blocklist): tx={norm.get('tx_id')}")
        return {"ok": True, "suppressed": True, "reason": "name_blocklist"}

    asset = (norm.get("asset") or "").upper()
    investor = norm.get("src_name") or norm.get("dst_name") or "Unknown"
    tx_id = norm.get("tx_id") or ""
    dst_type = (norm.get("dst_type") or "").upper()
    dst_name = norm.get("dst_name") or ""
    dst_id_full = norm.get("dst_id_full") or ""
    amount_str = fmt_amount(norm.get("amount"))

    # ── Rule 1: ETH_TEST5 -> Internal Wallet N/A (specific wallet id) => MINT/BURN
    is_eth_test5_to_qcdt_internal = (
        asset == "ETH_TEST5" and
        dst_type == "INTERNAL_WALLET" and
        dst_name == "N/A" and
        (dst_id_full.startswith(QCDT_INTERNAL_WALLET_ID) or dst_id_full == QCDT_INTERNAL_WALLET_ID)
    )
    if is_eth_test5_to_qcdt_internal:
        msg = (
            "🕒 Fireblocks QCDT MINT/BURN Transaction Detected \n"
            f"Investor: {escape_html(investor)}\n"
            f"Tx: {escape_html(tx_id)}\n\n"
            "Action: Fund Admin to review and approve Investor's mint/burn request on DMZ portal, "
            "followed by approving mint/burn on Fireblocks app."
        )
        await send_to_telegram(msg)
        logging.info(f"Mint/Burn alert sent: tx={tx_id}")
        return {"ok": True, "alert": "mint_burn"}

    # ── Rule 2: QCDT_B75VRLGX_QIBD -> One Time Address N/A => WITHDRAWAL
    is_qcdt_to_one_time = (
        asset == "QCDT_B75VRLGX_QIBD" and
        dst_type == "ONE_TIME_ADDRESS" and
        dst_name == "N/A"
    )
    if is_qcdt_to_one_time:
        # Show "QCDT" instead of the long token code in the Amount line
        pretty_amount = f"{amount_str} QCDT" if amount_str else "QCDT"
        msg = (
            "🕒 Fireblocks QCDT Withdrawal Request Detected \n"
            f"Investor: {escape_html(investor)}\n"
            f"Amount: {escape_html(pretty_amount)}\n"
            f"Tx: {escape_html(tx_id)}\n\n"
            "Action: Fund Admin to review and approve Investor's QCDT withdrawal request. "
            "To check investor's destination address on Fireblocks App before approving."
        )
        await send_to_telegram(msg)
        logging.info(f"Withdrawal alert sent: tx={tx_id}")
        return {"ok": True, "alert": "withdrawal"}

    # suppress everything else
    logging.info(f"Suppressed (no rule match): asset={asset} dst={dst_type}/{dst_name} tx={tx_id}")
    return {"ok": True, "suppressed": True, "reason": "no_rule_match"}
