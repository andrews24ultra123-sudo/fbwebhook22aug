# main.py
# Fireblocks -> Telegram webhook (FastAPI)
# - Mint/Burn alert:
#     * asset in MINT_ASSET_IDS (env, defaults to ETH_TEST5)
#     * To = Internal Wallet (name "N/A")
#     * If QCDT_INTERNAL_WALLET_IDS env is set (comma-separated), destination wallet id must start with one of those
# - Withdrawal alert:
#     * asset in QCDT_TOKEN_IDS (env, defaults to QCDT_B75VRLGX_QIBD)
#     * To = One Time Address (name "N/A")
#     * Amount shown with QCDT_DISPLAY_SYMBOL (env, defaults to "QCDT")
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

# ─── Telegram bot credentials ────────────────────────────────
TELEGRAM_BOT_TOKEN = "8267279608:AAEgyQ0bJO338F1Is34IXZ7unAl1khpt2qI"
TELEGRAM_CHAT_ID   = "-4680966417"   # group chat id

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

# ─── Controls & Filters ───────────────────────────────────────
ALLOW_UNVERIFIED = True      # flip to False for production
FILTER_NAME_BLOCKLIST = {"op@fundadmin.com"}  # suppress by From/To name

# Assets & IDs made configurable via env
# - QCDT_TOKEN_IDS: comma-separated list of your token identifiers (e.g. "QCDT_B75VRLGX_QIBD,NEW_TOKEN_ABC")
# - QCDT_DISPLAY_SYMBOL: how to print the token in messages (default "QCDT")
# - MINT_ASSET_IDS: assets that represent the on-chain funding leg for mint/burn (default "ETH_TEST5")
# - QCDT_INTERNAL_WALLET_IDS: optional comma-separated internal wallet id/prefixes to restrict the mint rule
def _parse_csv_env(name: str, default: str = ""):
    raw = os.getenv(name, default).strip()
    return [s.strip() for s in raw.split(",") if s.strip()]

QCDT_TOKEN_IDS       = [a.upper() for a in _parse_csv_env("QCDT_TOKEN_IDS", "QCDT_B75VRLGX_QIBD")]
QCDT_DISPLAY_SYMBOL  = os.getenv("QCDT_DISPLAY_SYMBOL", "QCDT").strip() or "QCDT"
MINT_ASSET_IDS       = [a.upper() for a in _parse_csv_env("MINT_ASSET_IDS", "ETH_TEST5")]
ALLOWED_INT_WALLET_IDS = _parse_csv_env("QCDT_INTERNAL_WALLET_IDS", "")  # keep original casing; we do startswith

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
        return str(x)

def verify_rsa(raw_body: bytes, signature_b64: str, public_key_pem: str) -> bool:
    """Try RSA PKCS1v15 first, then RSA-PSS (both SHA-512)."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature = base64.b64decode(signature_b64)
        try:
            public_key.verify(signature, raw_body, padding.PKCS1v15(), hashes.SHA512())
            return True
        except InvalidSignature:
            pass
        public_key.verify(
            signature,
            raw_body,
            padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=hashes.SHA512().digest_size),
            hashes.SHA512(),
        )
        return True
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
    if isinstance(actor, dict):
        return str(actor.get("type") or ""), str(actor.get("name") or ""), str(actor.get("id") or ""), str(actor.get("id") or "")
    return "", str(actor or ""), "", ""

def coalesce_event(payload: dict) -> dict:
    if not isinstance(payload, dict): return {}
    evt_type = payload.get("type") or payload.get("eventType")
    status   = payload.get("status") or payload.get("txStatus")
    tx_id    = payload.get("id") or payload.get("transactionId")  # full FB tx id
    asset    = payload.get("assetId") or payload.get("asset") or payload.get("currency")
    amount   = payload.get("amount") or payload.get("value")
    src      = payload.get("source") or payload.get("from")
    dst      = payload.get("destination") or payload.get("to")
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
        "tx_id": str(tx_id or ""),
        "asset": str(asset or ""),
        "amount": amount,
        "src_type": src_type, "src_name": src_name, "src_id": src_id, "src_id_full": src_id_full,
        "dst_type": dst_type, "dst_name": dst_name, "dst_id": dst_id, "dst_id_full": dst_id_full,
    }

def should_suppress_by_name(norm: dict) -> bool:
    for bad in FILTER_NAME_BLOCKLIST:
        if bad.lower() in norm.get("src_name","").lower() or bad.lower() in norm.get("dst_name","").lower():
            return True
    return False

def match_internal_wallet(dst_type: str, dst_name: str, dst_id_full: str) -> bool:
    """
    True if destination matches your internal wallet rule for mint/burn:
      - type INTERNAL_WALLET
      - name "N/A"
      - if ALLOWED_INT_WALLET_IDS provided: dst_id_full startswith any allowed ID
      - if none provided: accept ANY internal wallet named "N/A"
    """
    if (dst_type or "").upper() != "INTERNAL_WALLET":
        return False
    if (dst_name or "") != "N/A":
        return False
    if not ALLOWED_INT_WALLET_IDS:
        return True
    did = dst_id_full or ""
    return any(did.startswith(allow) for allow in ALLOWED_INT_WALLET_IDS)

# ─────────────────────────── Routes ───────────────────────────
@app.get("/")
async def root():
    return {
        "ok": True,
        "webhook": "/fireblocks/webhook",
        "verification": "skipped" if ALLOW_UNVERIFIED else "rsa/secret",
        "mint_assets": MINT_ASSET_IDS,
        "qcdt_token_ids": QCDT_TOKEN_IDS,
        "qcdt_symbol": QCDT_DISPLAY_SYMBOL,
        "allowed_internal_wallet_ids": ALLOWED_INT_WALLET_IDS or "ANY (name='N/A')",
    }

@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.post("/fireblocks/webhook")
async def fireblocks_webhook(
    request: Request,
    fireblocks_signature: str | None = Header(default=None, convert_underscores=False),
    x_fireblocks_signature: str | None = Header(default=None, convert_underscores=False),
    x_webhook_secret: str | None = Header(default=None, convert_underscores=False),
):
    raw = await request.body()
    sig = fireblocks_signature or x_fireblocks_signature
    verified = False
    if FIREBLOCKS_PUBLIC_KEY_PEM.strip() and sig:
        verified = verify_rsa(raw, sig, FIREBLOCKS_PUBLIC_KEY_PEM)
    if not verified and FIREBLOCKS_WEBHOOK_SECRET.strip():
        verified = verify_shared_secret(x_webhook_secret, FIREBLOCKS_WEBHOOK_SECRET)
    if not verified and not ALLOW_UNVERIFIED:
        raise HTTPException(status_code=401, detail="Signature verification failed")

    try: payload = json.loads(raw.decode("utf-8"))
    except Exception: payload = {}
    norm = coalesce_event(payload)

    if should_suppress_by_name(norm):
        logging.info(f"Suppressed: name blocklist hit tx={norm.get('tx_id')}")
        return {"ok": True, "suppressed": "name_blocklist"}

    asset_upper = (norm.get("asset") or "").upper()
    investor = norm.get("src_name") or norm.get("dst_name") or "Unknown"
    tx_id = norm.get("tx_id") or ""
    dst_type = (norm.get("dst_type") or "").upper()
    dst_name = norm.get("dst_name") or ""
    dst_id_full = norm.get("dst_id_full") or ""
    amount_str = fmt_amount(norm.get("amount"))

    # Rule 1: MINT/BURN (funding leg) → Internal Wallet
    if asset_upper in MINT_ASSET_IDS and match_internal_wallet(dst_type, dst_name, dst_id_full):
        msg = (
            "⏰ Fireblocks QCDT MINT/BURN Transaction Detected \n"
            f"Investor: {escape_html(investor)}\n"
            f"Tx: {escape_html(tx_id)}\n\n"
            "Action: Fund Admin to review and approve Investor's mint/burn request on DMZ portal, "
            "followed by approving mint/burn on Fireblocks app."
        )
        await send_to_telegram(msg)
        return {"ok": True, "alert": "mint_burn"}

    # Rule 2: QCDT Withdrawal → One Time Address "N/A"
    if (asset_upper in QCDT_TOKEN_IDS) and dst_type == "ONE_TIME_ADDRESS" and dst_name == "N/A":
        pretty_amount = f"{amount_str} {QCDT_DISPLAY_SYMBOL}" if amount_str else QCDT_DISPLAY_SYMBOL
        msg = (
            "⏰ Fireblocks QCDT Withdrawal Request Detected \n"
            f"Investor: {escape_html(investor)}\n"
            f"Amount: {escape_html(pretty_amount)}\n"
            f"Tx: {escape_html(tx_id)}\n\n"
            "Action: Fund Admin to review and approve Investor's QCDT withdrawal request. "
            "To check investor's destination address on Fireblocks App before approving."
        )
        await send_to_telegram(msg)
        return {"ok": True, "alert": "withdrawal"}

    logging.info(f"Suppressed: no rule match asset={asset_upper} dst={dst_type}/{dst_name} tx={tx_id}")
    return {"ok": True, "suppressed": "no_rule_match"}
