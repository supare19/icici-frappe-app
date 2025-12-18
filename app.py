from flask import Flask, request, jsonify
import os
import json
import base64
from datetime import datetime

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509

app = Flask(__name__)

# ======== CONFIG =========

# ICICI sandbox URL
ICICI_URL = "https://apibankingonesandbox.icicibank.com/api/v1/composite-validation"

# From ICICI email
ICICI_API_KEY = "ueRq0LmkrqovbIB02DebEE2PPOtpfCf7"
X_PRIORITY    = "0010"
SERVICE       = "IMPS_NAME_INQUIRY"

# Shared secret between ERPNext and this middleware
# >>> MUST MATCH the value you put in ERPNext server script <<<
SHARED_SECRET = "CHANGE_THIS_TO_A_LONG_RANDOM_STRING"

# ICICI public certificate (same as icici_public.pem you pasted)
ICICI_CERT_PEM = b"""-----BEGIN CERTIFICATE-----
MIIE7jCCAtagAwIBAgIIWmFBujLqylAwDQYJKoZIhvcNAQEMBQAwFTETMBEGA1UEAwwKcnNhX2Fw
aWtleTAeFw0xODEwMzAwNDQ3MThaFw0yMzEwMjkwNDQ3MThaMBUxEzARBgNVBAMMCnJzYV9hcGlr
ZXkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCwjBVK1CLppIwsFm7e+Fp85Hk1Mw2n
5Nc/DKT/pWhpJB8OdlpJA9iF23hrxfbXkrBfCkgvV4Ek4fY1byOnkA7hZq4dYTASCAm89oLwWDNm
0OGNh7E6T7/JoNtjtT0Gh8lJTvpUgHFGg3tiYCScAqul+fS6Rc8+5THk3L9zLzme6eqjkzwBx/ZV
XBIZlAwFkVKbfLFg51LiVoOUz6zXD7nAsMyNhKAgybvqulV07eGzafZ1IBgzpcw5qo0PAd1mTqfy
U+CK9hVeNPPspT16qQWd5xa+fa6BEjuGCumVnFLTbSTRAF5h3QAfvMlkpLdejlXJwvTVQ79Zg5C8
Hu/yWB7tOJBncIKue7KSpwn+vkMws79wpAB5mL4tD3kVCDf2Og7wbtt87v5rcazxF7eZFbsADzHV
oSftdkw5S7iXgh82/CHbRXhzPfG8Zd2v1ksW+Bfnn3czEIMGOSJrKfMbyCYtVMihoi0/L6SHA7++
N9aRrQvfK9PeXnlHgf8pErGUdpjnwdV0tu5atSgf/iBuRgVgUL6t6MFbnBsTQUmZYiQRcsqxOVdy
yfp4DOLgFHGJ1D/isgR/ypalIXMmhuK8GdZ7hukEDX2Dc3js8OkPnFLq6Ps4NIGESfbZSeyINoZX
5GGxdgD/GpokKMHr5bsI3TQujCvzuxShPhUArzCs6TgPmwIDAQABo0IwQDAdBgNVHQ4EFgQUyNoW
eeLVSzVybz7gcZnZlj01cv4wHwYDVR0jBBgwFoAUyNoWeeLVSzVybz7gcZnZlj01cv4wDQYJKoZI
hvcNAQEMBQADggIBADuwEh31OI66oSMB6a79Pd6WSqiyD2NBskdRF7st7CRP5vqeH4P/4srNFAqC
9CjsOmXmSpZFckYQ4zgtqnVQBY7jQlCuSHmg8/Lr1qIzRsMvQmhvp6DJ+bEfQgqcJ+a6tR9cH6hD
VahoMZDEpt3J0fIp30z+O7wJ03K6q5Di/rNey6Ac3GoZwlCi8OFCTmwihcn56I+ssxAqzlq53hzO
iBLLmcMTrWSJWePPkYEhrbBxywg1qJRRGWwkfr1dbRZ22umLHU0R/QdK+jQtqyzghqJpd3T/lHzK
uzAsa0s1R+qMqurKu6mulcLp/XmZpY+Fm4T0WRXzcZBf9trkCSO2Z3VvkCTeGu/WAi3UQpx4HfGr
x02m/h8CHCPPO+PKYthpvSR+0jmiVBaaBo029UG0i2oYBTckng2sy0fx0E+rHnR7pk5Worv8BMm5
sewPUkDDJMZhLtm/bd/VxlI/b56vEA7HvupSWzc7xXV8lZOHVEUAotrlXz+Je2MkEEQIDnYUOYhw
78yFMJJddK9tJVRy8tr8I2j6Zi62jQp/Zltq5JOwpOw/9poovd9wgeRBjuFnscoR/YWrNdPjsjpJ
g/CCb6mthz4R2Mu4enD1YghW7w5darrlUHaYAk+SnwWhMwDwZWWfrVNeEaNq/t/gRm/Ljy+Of3lA
nztA1PrT4bk1KvZX
-----END CERTIFICATE-----"""

# ===== Encryption helpers =====

def load_icici_public_key():
    cert = x509.load_pem_x509_certificate(ICICI_CERT_PEM, backend=default_backend())
    return cert.public_key()

def aes_encrypt(plaintext: bytes):
    key = os.urandom(32)   # 256-bit
    iv = os.urandom(16)    # 128-bit
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len]) * pad_len

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return key, iv, ciphertext

def encrypt_inner_payload(inner_dict):
    inner_json = json.dumps(inner_dict, separators=(",", ":")).encode("utf-8")
    aes_key, iv, cipher_bytes = aes_encrypt(inner_json)

    pubkey = load_icici_public_key()
    enc_key = pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "requestId": inner_dict["TranRefNo"],
        "service": SERVICE,
        "encryptedKey": base64.b64encode(enc_key).decode("ascii"),
        "encryptedData": base64.b64encode(cipher_bytes).decode("ascii"),
        "oaepHashingAlgorithm": "NONE",  # as per ICICI sample
        "iv": base64.b64encode(iv).decode("ascii"),
        "clientInfo": "",
        "optionalParam": "",
    }

# ===== Route =====

@app.route("/icici/name_inquiry", methods=["POST"])
def icici_name_inquiry():
    # ---- Auth check: allow only ERPNext with correct shared secret ----
    header_secret = request.headers.get("X-ERP-SECRET")
    if header_secret != SHARED_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}

    bene_acc   = data.get("BeneAccNo")
    bene_ifsc  = data.get("BeneIFSC")
    rem_name   = data.get("RemName")
    rem_mobile = data.get("RemMobile")
    tran_ref   = data.get("TranRefNo") or datetime.now().strftime("%Y%m%d%H%M%S")

    if not (bene_acc and bene_ifsc and rem_name and rem_mobile):
        return jsonify({"error": "Missing required fields"}), 400

    inner = {
        "BeneAccNo": bene_acc,
        "BeneIFSC": bene_ifsc,
        "TranRefNo": tran_ref,
        "PaymentRef": "IMPSTransfer",
        "RemName": rem_name,
        "RemMobile": rem_mobile,
        "RetailerCode": "rcode",
        "PassCode": "447c4524c9074b8c97e3a3c40ca7458d",
        "TransactionDate": tran_ref,
        "Channel": "APICORPBC",
        "BcID": "IBCKer00055",
    }

    envelope = encrypt_inner_payload(inner)

    headers = {
        "Content-Type": "application/json",
        "accept": "application/json",
        "apikey": ICICI_API_KEY,
        "x-priority": X_PRIORITY,
    }

    resp = requests.post(ICICI_URL, json=envelope, headers=headers, timeout=60)

    try:
        resp_json = resp.json()
    except Exception:
        resp_json = {"raw": resp.text}

    return jsonify({
        "success": resp.ok,
        "http_status": resp.status_code,
        "request_sent_to_icici": envelope,
        "icici_response_encrypted": resp_json
    })

if __name__ == "__main__":
    # For local testing
    app.run(host="0.0.0.0", port=5000, debug=True)
