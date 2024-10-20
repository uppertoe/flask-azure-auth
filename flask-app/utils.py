import base64
import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jwt import ExpiredSignatureError, InvalidSignatureError, InvalidTokenError


class TokenDecoder:
    def __init__(self, tenant_id, client_id):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.jwks_url = (
            f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        )

    def base64url_to_int(self, val):
        """Decodes a base64url-encoded string to an integer."""
        val = val + "=" * (4 - len(val) % 4)  # Add padding if necessary
        decoded = base64.urlsafe_b64decode(val)
        return int.from_bytes(decoded, "big")

    def get_public_key(self, jwks, kid):
        """Extracts the public key based on the 'kid' from the JWT."""
        for key in jwks["keys"]:
            if key["kid"] == kid:
                n = self.base64url_to_int(key["n"])  # Modulus
                e = self.base64url_to_int(key["e"])  # Exponent
                public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

                return public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
        raise ValueError("Public key not found.")

    def decode_token(self, id_token, verify_signature=True):
        """Decodes the JWT and returns the claims."""
        try:
            # Get the unverified token header to extract 'kid'
            unverified_header = jwt.get_unverified_header(id_token)
            kid = unverified_header["kid"]

            if verify_signature:
                # Fetch the public keys (JWKS) from Azure AD
                jwks = requests.get(self.jwks_url).json()

                # Get the corresponding public key based on 'kid'
                public_key_pem = self.get_public_key(jwks, kid)

                # Decode the token with signature verification
                claims = jwt.decode(
                    id_token,
                    public_key_pem,
                    algorithms=["RS256"],
                    audience=self.client_id,
                )
            else:
                # Decode without signature verification (for debugging)
                claims = jwt.decode(id_token, options={"verify_signature": False})

            return claims

        except ExpiredSignatureError:
            raise InvalidTokenError("Token has expired.")
        except InvalidSignatureError:
            raise InvalidTokenError("Invalid token signature.")
        except InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}")
        except Exception as e:
            raise InvalidTokenError(f"Error decoding token: {str(e)}")
