from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from datetime import timedelta, timezone, datetime
import argparse
import base64
import hashlib
import logging
import sys
import os
import jwt  # PyJWT for generating tokens

# Load passphrase from environment variable
PRIVATE_KEY_PASSPHRASE = os.getenv("RSA_PRIVATE_KEY_PASSPHRASE")

logger = logging.getLogger(__name__)

class JWTGenerator(object):
    LIFETIME = timedelta(minutes=59)
    RENEWAL_DELTA = timedelta(minutes=54)
    ALGORITHM = "RS256"

    def __init__(self, account, user, private_key_file_path, lifetime=LIFETIME, renewal_delay=RENEWAL_DELTA):
        logger.info(f"Creating JWTGenerator for account: {account}, user: {user}")

        self.account = self.prepare_account_name_for_jwt(account)
        self.user = user.upper()
        self.qualified_username = self.account + "." + self.user
        self.lifetime = lifetime
        self.renewal_delay = renewal_delay
        self.private_key_file_path = private_key_file_path
        self.renew_time = datetime.now(timezone.utc)
        self.token = None

        # 🔹 Load private key with passphrase from environment variable
        with open(self.private_key_file_path, 'rb') as pem_in:
            pemlines = pem_in.read()
            self.private_key = load_pem_private_key(
                pemlines,
                password=PRIVATE_KEY_PASSPHRASE.encode() if PRIVATE_KEY_PASSPHRASE else None,
                backend=default_backend()
            )

    def get_token(self):
        now = datetime.now(timezone.utc)  # Current time

        # Convert lifetime to int if it is a string
        lifetime_minutes = int(self.lifetime) if isinstance(self.lifetime, str) else self.lifetime

        payload = {
            "iss": self.qualified_username + "." + self.calculate_public_key_fingerprint(self.private_key),
            "sub": self.qualified_username,
            "iat": now,
            "exp": now + lifetime_minutes 
        }

        self.token = jwt.encode(payload, key=self.private_key, algorithm=self.ALGORITHM)
        return self.token

    def calculate_public_key_fingerprint(self, private_key):
        public_key_raw = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        sha256hash = hashlib.sha256()
        sha256hash.update(public_key_raw)
        return 'SHA256:' + base64.b64encode(sha256hash.digest()).decode('utf-8')

    def prepare_account_name_for_jwt(self, raw_account):
        if ".global" not in raw_account:
            idx = raw_account.find(".")
            if idx > 0:
                raw_account = raw_account[:idx]
        else:
            idx = raw_account.find("-")
            if idx > 0:
                raw_account = raw_account[:idx]
        return raw_account.upper()

def main():
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    cli_parser = argparse.ArgumentParser()
    cli_parser.add_argument('--account', required=True)
    cli_parser.add_argument('--user', required=True)
    cli_parser.add_argument('--private_key_file_path', required=True)
    args = cli_parser.parse_args()
    token = JWTGenerator(args.account, args.user, args.private_key_file_path).get_token()
    print("JWT:", token)

if __name__ == "__main__":
    main()
