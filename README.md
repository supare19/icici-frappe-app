# ICICI IMPS Name Inquiry API

A middleware application for ICICI Bank's IMPS Name Inquiry API integration.

## Features

- Flask-based API endpoint (`app.py`)
- FastAPI-based API endpoint (`main.py`)
- Encrypted payload handling using AES and RSA encryption
- ICICI Bank API integration

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up environment variables (for `main.py`):
```bash
export ICICI_URL="https://apibankingonesandbox.icicibank.com/api/v1/composite-validation"
export ICICI_API_KEY="your_api_key"
export X_PRIORITY="0010"
export ICICI_PUBKEY_PATH="icici_cert.pem"
export ICICI_SERVICE="IMPS_NAME_INQUIRY"
```

3. Run the Flask app:
```bash
python app.py
```

4. Run the FastAPI app:
```bash
uvicorn main:app --reload
```

## API Endpoints

### Flask (`app.py`)
- `POST /icici/name_inquiry` - IMPS name inquiry endpoint

### FastAPI (`main.py`)
- `GET /` - Health check endpoint
- `POST /icici/verify` - IMPS verification endpoint

## Security Note

⚠️ **Important**: This repository contains example code. Before deploying to production:
- Remove hardcoded API keys and secrets
- Use environment variables or secure configuration management
- Store certificates securely
- Update the `SHARED_SECRET` in `app.py`

## License

[Add your license here]

