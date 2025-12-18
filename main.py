from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
import os
import json
import base64
import secrets
import requests

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = FastAPI()

# ---------- CONFIG FROM ENV ----------
ICICI_URL = os.getenv(
    "ICICI_URL",
    "https://apibankingonesandbox.icicibank.com/api/v1/composite-validation"
)
ICICI_API_KEY = os.getenv("ICICI_API_KEY")
X_PRIORITY = os.getenv("X_PRIORITY", "0010")
ICICI_PUBKEY_PATH = os.getenv("ICICI_PUBKEY_PATH", "icici_cert.pem")
ICICI_SERVICE = os.getenv("ICICI_SERVICE", "IMPS_NAME_INQUIRY")

print("=== LOADED CONFIG ===")
print("ICICI_URL:", ICICI_URL)
print("ICICI_API_KEY (first 6):", (ICICI_API_KEY or "")[:6])
print("X_PRIORITY:", X_PRIORITY)
print("PUBKEY PATH:", ICICI_PUBKEY_PATH)
print("SERVICE:", ICICI_SERVICE)


class VerifyRequest(BaseModel):
    BeneAccNo: str
    BeneIFSC: str
    TranRefNo: str | None = None
    PaymentRef: str | None = "IMPSTransfer"
    RemName: str
    RemMobile: str
    RetailerCode: str
    PassCode: str
    TransactionDate: str | None = None
    Channel: str
    BcID: str


def load_icici_public_key():
    with open(ICICI_PUBKEY_PATH, "rb") as f:
        data = f.read()
    cert = x509.load_pem_x509_certificate(data, backend=default_backend())
    return cert.public_key()


def encrypt_inner_payload(inner_body: dict, request_id: str) -> dict:
    plaintext = json.dumps(inner_body, separators=(",", ":")).encode("utf-8")

    aes_key = secrets.token_bytes(32)  # 256-bit
    iv = secrets.token_bytes(16)       # 128-bit

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    pubkey = load_icici_public_key()
    encrypted_key = pubkey.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "requestId": request_id,
        "service": ICICI_SERVICE,
        "encryptedKey": base64.b64encode(encrypted_key).decode("ascii"),
        "encryptedData": base64.b64encode(ciphertext).decode("ascii"),
        "oaepHashingAlgorithm": "NONE",
        "iv": base64.b64encode(iv).decode("ascii"),
        "clientInfo": "",
        "optionalParam": "",
    }


@app.get("/")
def health():
    return {"status": "ok", "message": "ICICI IMPS Name Inquiry API is running"}


@app.post("/icici/verify")
def icici_verify(req: VerifyRequest):
    ts = datetime.now().strftime("%Y%m%d%H%M%S")

    inner_body = {
        "BeneAccNo": req.BeneAccNo,
        "BeneIFSC": req.BeneIFSC,
        "TranRefNo": req.TranRefNo or ts,
        "PaymentRef": req.PaymentRef or "IMPSTransfer",
        "RemName": req.RemName,
        "RemMobile": req.RemMobile,
        "RetailerCode": req.RetailerCode,
        "PassCode": req.PassCode,
        "TransactionDate": req.TransactionDate or ts,
        "Channel": req.Channel,
        "BcID": req.BcID,
    }

    print("=== INNER BODY (PLAIN) ===")
    print(inner_body)

    request_id = inner_body["TranRefNo"]

    try:
        envelope = encrypt_inner_payload(inner_body, request_id)
    except Exception as e:
        return {"success": False, "error": f"Encryption failed: {e}"}

    print("=== ENVELOPE SENT TO ICICI ===")
    print(envelope)

    headers = {
        "Content-Type": "application/json",
        "accept": "application/json",
        "apikey": ICICI_API_KEY,
        "x-priority": X_PRIORITY,
    }

    print("=== HEADERS ===")
    print(headers)

    try:
        resp = requests.post(ICICI_URL, json=envelope, headers=headers, timeout=60)
    except Exception as e:
        return {"success": False, "error": f"Request error: {e}"}

    try:
        resp_json = resp.json()
    except Exception:
        resp_json = None

    return {
        "success": True,
        "http_status": resp.status_code,
        "request_sent_to_icici": envelope,
        "icici_response_encrypted": resp_json or resp.text,
    }
