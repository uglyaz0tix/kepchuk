import hashlib
import hmac
import json
import sys
import time
import uuid
import requests

BASE_URL = "http://127.0.0.1:8080"


def compute_signature(bot_id: str, bot_secret: str, timestamp: int, nonce: str, body: bytes) -> str:
    body_sha256 = hashlib.sha256(body).hexdigest()
    time_window = str(timestamp // 300)
    message = f"{bot_id}:{timestamp}:{nonce}:{body_sha256}"
    payload = f"{time_window}:{message}".encode("utf-8")
    return hmac.new(bot_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


class SecurityTestSuite:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.passed = 0
        self.failed = 0

    def log_result(self, name: str, success: bool, detail: str = ""):
        if success:
            self.passed += 1
            print(f"  [PASS] {name}")
        else:
            self.failed += 1
            print(f"  [FAIL] {name} - {detail}")

    def register_bot(self, bot_id: str) -> dict:
        url = f"{self.base_url}/kep/auth/register"
        resp = requests.post(url, json={"bot_id": bot_id}, timeout=5)
        if resp.status_code != 200:
            raise RuntimeError(f"failed to register bot {bot_id}: {resp.status_code} {resp.text}")
        return resp.json()

    def test_baseline_valid_request(self, bot: dict):
        bot_id = bot["bot_id"]
        secret = bot["bot_secret"]
        api_key = bot["api_key"]

        ts = int(time.time())
        nonce = str(uuid.uuid4())
        sig = compute_signature(bot_id, secret, ts, nonce, b"")

        headers = {
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(ts),
            "X-Nonce": nonce,
            "X-Signature": sig,
        }
        resp = requests.get(f"{self.base_url}/kep/subs/status/sec_user_1", headers=headers, timeout=5)
        self.log_result(
            "baseline valid request accepted",
            resp.status_code == 200,
            f"expected 200, got {resp.status_code}",
        )

    def test_missing_headers(self, bot: dict):
        bot_id = bot["bot_id"]
        secret = bot["bot_secret"]
        api_key = bot["api_key"]
        ts = int(time.time())
        nonce = str(uuid.uuid4())
        sig = compute_signature(bot_id, secret, ts, nonce, b"")

        base_headers = {
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(ts),
            "X-Nonce": nonce,
            "X-Signature": sig,
        }

        for header_to_omit in base_headers:
            headers = {k: v for k, v in base_headers.items() if k != header_to_omit}
            resp = requests.get(f"{self.base_url}/kep/subs/status/sec_user_1", headers=headers, timeout=5)
            self.log_result(
                f"rejection on missing header: {header_to_omit}",
                resp.status_code == 401,
                f"expected 401, got {resp.status_code}",
            )

    def test_invalid_api_key(self, bot: dict):
        bot_id = bot["bot_id"]
        secret = bot["bot_secret"]
        ts = int(time.time())
        nonce = str(uuid.uuid4())
        sig = compute_signature(bot_id, secret, ts, nonce, b"")

        headers = {
            "X-Bot-ID": bot_id,
            "X-API-Key": "ak_live_forged_key_00000000000000000000000000000000",
            "X-Timestamp": str(ts),
            "X-Nonce": nonce,
            "X-Signature": sig,
        }
        resp = requests.get(f"{self.base_url}/kep/subs/status/sec_user_1", headers=headers, timeout=5)
        self.log_result(
            "rejection on invalid api key",
            resp.status_code == 401,
            f"expected 401, got {resp.status_code}",
        )

    def test_timestamp_ttl_window(self, bot: dict):
        bot_id = bot["bot_id"]
        secret = bot["bot_secret"]
        api_key = bot["api_key"]

        # expired timestamp in past (> 300s)
        expired_ts = int(time.time()) - 305
        nonce_past = str(uuid.uuid4())
        sig_past = compute_signature(bot_id, secret, expired_ts, nonce_past, b"")
        headers_past = {
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(expired_ts),
            "X-Nonce": nonce_past,
            "X-Signature": sig_past,
        }
        resp = requests.get(f"{self.base_url}/kep/subs/status/sec_user_1", headers=headers_past, timeout=5)
        self.log_result(
            "rejection on expired past timestamp (>300s)",
            resp.status_code == 401,
            f"expected 401, got {resp.status_code}",
        )

        # skewed timestamp in future (> 300s)
        future_ts = int(time.time()) + 305
        nonce_future = str(uuid.uuid4())
        sig_future = compute_signature(bot_id, secret, future_ts, nonce_future, b"")
        headers_future = {
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(future_ts),
            "X-Nonce": nonce_future,
            "X-Signature": sig_future,
        }
        resp = requests.get(f"{self.base_url}/kep/subs/status/sec_user_1", headers=headers_future, timeout=5)
        self.log_result(
            "rejection on skewed future timestamp (>300s)",
            resp.status_code == 401,
            f"expected 401, got {resp.status_code}",
        )

    def test_nonce_replay_attack(self, bot: dict):
        bot_id = bot["bot_id"]
        secret = bot["bot_secret"]
        api_key = bot["api_key"]

        ts = int(time.time())
        nonce = str(uuid.uuid4())
        sig = compute_signature(bot_id, secret, ts, nonce, b"")

        headers = {
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(ts),
            "X-Nonce": nonce,
            "X-Signature": sig,
        }

        # first request should succeed
        first = requests.get(f"{self.base_url}/kep/subs/status/sec_user_1", headers=headers, timeout=5)
        # exact replay of the same nonce must be rejected
        replay = requests.get(f"{self.base_url}/kep/subs/status/sec_user_1", headers=headers, timeout=5)

        self.log_result(
            "rejection on nonce replay attack (anti-replay cache)",
            first.status_code == 200 and replay.status_code == 409,
            f"first={first.status_code}, replay={replay.status_code}",
        )

    def test_body_tampering_vector(self, bot: dict):
        bot_id = bot["bot_id"]
        secret = bot["bot_secret"]
        api_key = bot["api_key"]

        legitimate_payload = json.dumps({"user_id": "sec_user_2", "tokens": 10, "reason": "normal"}).encode("utf-8")
        malicious_payload = json.dumps({"user_id": "sec_user_2", "tokens": 999999, "reason": "exploit"}).encode("utf-8")

        ts = int(time.time())
        nonce = str(uuid.uuid4())
        # compute signature over legitimate payload
        sig = compute_signature(bot_id, secret, ts, nonce, legitimate_payload)

        headers = {
            "Content-Type": "application/json",
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(ts),
            "X-Nonce": nonce,
            "X-Signature": sig,
        }

        # send tampered malicious payload with the signature of the legitimate one
        resp = requests.post(f"{self.base_url}/kep/subs/consume", data=malicious_payload, headers=headers, timeout=5)
        self.log_result(
            "rejection on tampered request body",
            resp.status_code == 401,
            f"expected 401, got {resp.status_code}",
        )

    def test_forged_signature_vector(self, bot: dict):
        bot_id = bot["bot_id"]
        api_key = bot["api_key"]
        ts = int(time.time())
        nonce = str(uuid.uuid4())

        forged_sig = "a" * 64
        headers = {
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(ts),
            "X-Nonce": nonce,
            "X-Signature": forged_sig,
        }
        resp = requests.get(f"{self.base_url}/kep/subs/status/sec_user_1", headers=headers, timeout=5)
        self.log_result(
            "rejection on forged signature bytes",
            resp.status_code == 401,
            f"expected 401, got {resp.status_code}",
        )

    def test_cross_bot_credential_spoofing(self, bot_a: dict, bot_b: dict):
        # bot b attempts to sign with its secret but claim bot a identity
        ts = int(time.time())
        nonce = str(uuid.uuid4())
        sig = compute_signature(bot_a["bot_id"], bot_b["bot_secret"], ts, nonce, b"")

        headers = {
            "X-Bot-ID": bot_a["bot_id"],
            "X-API-Key": bot_b["api_key"],
            "X-Timestamp": str(ts),
            "X-Nonce": nonce,
            "X-Signature": sig,
        }
        resp = requests.get(f"{self.base_url}/kep/subs/status/sec_user_1", headers=headers, timeout=5)
        self.log_result(
            "rejection on cross-bot credential spoofing",
            resp.status_code == 401,
            f"expected 401, got {resp.status_code}",
        )

    def test_insufficient_and_negative_balance_drain(self, bot: dict):
        bot_id = bot["bot_id"]
        secret = bot["bot_secret"]
        api_key = bot["api_key"]

        # 1. negative token consumption
        neg_body = json.dumps({"user_id": "sec_drain_user", "tokens": -50, "reason": "negative"}).encode("utf-8")
        ts = int(time.time())
        nonce = str(uuid.uuid4())
        sig = compute_signature(bot_id, secret, ts, nonce, neg_body)
        headers = {
            "Content-Type": "application/json",
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(ts),
            "X-Nonce": nonce,
            "X-Signature": sig,
        }
        resp_neg = requests.post(f"{self.base_url}/kep/subs/consume", data=neg_body, headers=headers, timeout=5)
        self.log_result(
            "rejection on negative token consumption attempt",
            resp_neg.status_code == 400,
            f"expected 400, got {resp_neg.status_code}",
        )

        # 2. excessive balance drain
        excess_body = json.dumps({"user_id": "sec_drain_user", "tokens": 99999999, "reason": "drain"}).encode("utf-8")
        ts = int(time.time())
        nonce = str(uuid.uuid4())
        sig = compute_signature(bot_id, secret, ts, nonce, excess_body)
        headers["X-Timestamp"] = str(ts)
        headers["X-Nonce"] = nonce
        headers["X-Signature"] = sig

        resp_excess = requests.post(f"{self.base_url}/kep/subs/consume", data=excess_body, headers=headers, timeout=5)
        self.log_result(
            "rejection on excessive balance drain exceeding funds",
            resp_excess.status_code == 400,
            f"expected 400, got {resp_excess.status_code}",
        )

    def test_blocked_user_security_enforcement(self, bot: dict):
        bot_id = bot["bot_id"]
        secret = bot["bot_secret"]
        api_key = bot["api_key"]

        user_id = f"blocked_victim_{uuid.uuid4().hex[:6]}"

        # block user
        block_body = json.dumps({"user_id": user_id, "reason": "abusive_behaviour", "duration_hours": 12}).encode("utf-8")
        ts = int(time.time())
        nonce = str(uuid.uuid4())
        sig = compute_signature(bot_id, secret, ts, nonce, block_body)
        headers = {
            "Content-Type": "application/json",
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(ts),
            "X-Nonce": nonce,
            "X-Signature": sig,
        }
        requests.post(f"{self.base_url}/kep/block/user", data=block_body, headers=headers, timeout=5)

        # try to consume tokens for blocked user
        consume_body = json.dumps({"user_id": user_id, "tokens": 10, "reason": "message"}).encode("utf-8")
        ts = int(time.time())
        nonce = str(uuid.uuid4())
        sig = compute_signature(bot_id, secret, ts, nonce, consume_body)
        headers["X-Timestamp"] = str(ts)
        headers["X-Nonce"] = nonce
        headers["X-Signature"] = sig

        resp = requests.post(f"{self.base_url}/kep/subs/consume", data=consume_body, headers=headers, timeout=5)
        self.log_result(
            "rejection on token consumption for blocked user",
            resp.status_code == 403,
            f"expected 403, got {resp.status_code}",
        )

    def test_secret_rotation_invalidation(self, bot: dict):
        bot_id = bot["bot_id"]
        old_secret = bot["bot_secret"]
        api_key = bot["api_key"]

        # rotate secret
        ts = int(time.time())
        nonce = str(uuid.uuid4())
        sig = compute_signature(bot_id, old_secret, ts, nonce, b"")
        headers = {
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(ts),
            "X-Nonce": nonce,
            "X-Signature": sig,
        }
        rot_resp = requests.post(f"{self.base_url}/kep/auth/rotate", headers=headers, timeout=5)
        if rot_resp.status_code != 200:
            self.log_result("secret rotation procedure", False, f"rotation failed: {rot_resp.status_code}")
            return

        new_secret = rot_resp.json()["bot_secret"]

        # verify that old secret is rejected
        ts_old = int(time.time())
        nonce_old = str(uuid.uuid4())
        sig_old = compute_signature(bot_id, old_secret, ts_old, nonce_old, b"")
        headers_old = {
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(ts_old),
            "X-Nonce": nonce_old,
            "X-Signature": sig_old,
        }
        old_resp = requests.get(f"{self.base_url}/kep/subs/status/sec_user_1", headers=headers_old, timeout=5)

        # verify that new secret is accepted
        ts_new = int(time.time())
        nonce_new = str(uuid.uuid4())
        sig_new = compute_signature(bot_id, new_secret, ts_new, nonce_new, b"")
        headers_new = {
            "X-Bot-ID": bot_id,
            "X-API-Key": api_key,
            "X-Timestamp": str(ts_new),
            "X-Nonce": nonce_new,
            "X-Signature": sig_new,
        }
        new_resp = requests.get(f"{self.base_url}/kep/subs/status/sec_user_1", headers=headers_new, timeout=5)

        success = (old_resp.status_code == 401) and (new_resp.status_code == 200)
        self.log_result(
            "invalidation of retired secret after rotation",
            success,
            f"old_resp={old_resp.status_code}, new_resp={new_resp.status_code}",
        )

    def run_all(self):
        print("=== Kepchuk Security Verification Test Suite ===")
        print(f"Target Server: {self.base_url}")

        try:
            health = requests.get(f"{self.base_url}/healthz", timeout=3)
            if health.status_code != 200:
                print(f"[ERROR] Target server healthcheck failed with status {health.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Target server unreachable at {self.base_url}")
            print("Please ensure the Kepchuk server is running (`cargo run --release`).")
            return False

        # provision test bots
        bot_a = self.register_bot(f"sec_bot_a_{uuid.uuid4().hex[:6]}")
        bot_b = self.register_bot(f"sec_bot_b_{uuid.uuid4().hex[:6]}")

        print("\nExecuting Security Control Vectors:")
        self.test_baseline_valid_request(bot_a)
        self.test_missing_headers(bot_a)
        self.test_invalid_api_key(bot_a)
        self.test_timestamp_ttl_window(bot_a)
        self.test_nonce_replay_attack(bot_a)
        self.test_body_tampering_vector(bot_a)
        self.test_forged_signature_vector(bot_a)
        self.test_cross_bot_credential_spoofing(bot_a, bot_b)
        self.test_insufficient_and_negative_balance_drain(bot_a)
        self.test_blocked_user_security_enforcement(bot_a)
        self.test_secret_rotation_invalidation(bot_a)

        total = self.passed + self.failed
        print("\n=== Test Results Summary ===")
        print(f"Total Vectors Checked : {total}")
        print(f"Passed Checks         : {self.passed}")
        print(f"Failed Checks         : {self.failed}")

        return self.failed == 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else BASE_URL
    suite = SecurityTestSuite(target)
    success = suite.run_all()
    sys.exit(0 if success else 1)
