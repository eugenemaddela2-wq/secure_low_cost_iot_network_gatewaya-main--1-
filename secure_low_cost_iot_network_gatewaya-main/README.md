# Secure Low-Cost IoT Network Gateway for POULTRYVANTAGE

Python prototype gateway for receiving third-party farm monitoring data, authenticating requests with HMAC-SHA256, buffering data when cloud forwarding fails, retrying queued data, logging gateway events, and exposing a lightweight admin API.

## Included features
- HMAC-SHA256 source authentication
- Device/source ID + shared secret
- Payload validation
- SQLite local buffering
- Retry queue for failed cloud forwarding
- Gateway event logging
- Connectivity and transmission status
- Basic latency measurement
- Backup of gateway database and logs
- Flask admin/API endpoints
- Test sender script

## Scope
This prototype assumes sensors/ESP32 and the POULTRYVANTAGE cloud/mobile app already exist. It does not develop or control sensors. Replace the sample cloud forwarder with the real POULTRYVANTAGE endpoint/Firebase integration when available.

## Quick start
1. Install Python 3.11+
2. Create a virtual environment
3. `pip install -r requirements.txt`
4. Copy `.env.example` to `.env`
5. Run `python app.py`
6. In another terminal run `python test_sender.py`

Default API: http://127.0.0.1:5000

## Main endpoints
- `POST /api/data` - receive signed monitoring payload
- `GET /api/status` - gateway status
- `GET /api/records` - recent records
- `GET /api/logs` - recent gateway logs
- `POST /api/retry` - retry buffered records
- `POST /api/backup` - create a backup

## HMAC signing
The sender signs the raw JSON request body with the device's shared secret using HMAC-SHA256 and sends:
- `X-Device-ID`
- `X-Signature`

## Disclaimer
This is a capstone prototype. It should be tested in a controlled environment before production use.
