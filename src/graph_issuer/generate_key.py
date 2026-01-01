import hashlib
from async_framework.validator import validate_model
from .validator_type import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
import base64

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def jwk_thumbprint(jwk: dict) -> str:
    canonical = {
        "e": jwk["e"],
        "kty": jwk["kty"],
        "n": jwk["n"],
    }
    s = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(s.encode("utf-8")).digest()
    return b64url_encode(digest)

def register_generate_key(sync_query, async_query):
    
    @async_query.register('issuer/generate_key')
    async def handle_generate_key(context, payload):

        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()

            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            numbers = public_key.public_numbers()
            n = numbers.n
            e = numbers.e

            n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
            e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")

            n_b64 = b64url_encode(n_bytes)
            e_b64 = b64url_encode(e_bytes)

            jwk = {
                "kty"   : "RSA",
                "use"   : "sig", 
                "alg"   : "RS256",
                "n"     : n_b64,
                "e"     : e_b64
            }
            jwk["kid"] = jwk_thumbprint(jwk)

            return {
                'status' : 'success',
                'private_key_pem' : pem_private,
                'public_key_pem'  : pem_public,
                'jwk'             : jwk
            }
        except Exception as e:
            return {
                'status' : 'failed',
                'error' : f'Can not generate key {str(e)}'
            }