import base64
import requests
import json
from nacl import public


class GitHubSecretUpdater:
    def __init__(self, repo, token, debug=False):
        self.repo = repo
        self.token = token
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }
        self.debug = debug

    def fetch_public_key(self):
        repo_owner, repo_name = self.repo.split("/")
        public_key_url = (
            f"https://api.github.com/repos/{self.repo}/actions/secrets/public-key"
        )
        public_key_response = requests.get(public_key_url, headers=self.headers)

        if public_key_response.status_code != 200:
            raise Exception(f"Failed to fetch public key: {public_key_response.text}")

        public_key_data = public_key_response.json()
        return public_key_data["key"], public_key_data["key_id"]

    def encrypt_secret(self, public_key_str, secret_value):
        public_key_bytes = base64.b64decode(public_key_str)
        public_key_obj = public.PublicKey(public_key_bytes)
        sealed_box = public.SealedBox(public_key_obj)
        encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
        return base64.b64encode(encrypted).decode("utf-8")

    def update_secret(self, secret_name, secret_value):
        print(f"Updating GitHub secret: {secret_name}...")

        if self.debug:
            # Don't send the secret in local development
            print(f"Secret {secret_name}: {secret_value}")
        else:
            public_key_str, key_id = self.fetch_public_key()
            encrypted_value = self.encrypt_secret(public_key_str, secret_value)

            secret_url = f"https://api.github.com/repos/{self.repo}/actions/secrets/{secret_name}"
            response = requests.put(
                secret_url,
                headers=self.headers,
                data=json.dumps({"encrypted_value": encrypted_value, "key_id": key_id}),
            )

            if response.status_code not in [201, 204]:
                raise Exception(
                    f"Failed to update GitHub secret {secret_name}: {response.text}"
                )

            print(f"Successfully updated GitHub secret: {secret_name}")
