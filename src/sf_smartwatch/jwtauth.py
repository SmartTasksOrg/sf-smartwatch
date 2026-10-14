"""JWT bearer tokens for the reset endpoint (council: OAuth2 JWT with the scope ``reset:agent``).

The monitor does not issue tokens: your identity provider does. Configure exactly one key:
    SMARTWATCH_JWT_HS256_SECRET   shared secret (at least 32 bytes) -> only HS256 is accepted
    SMARTWATCH_JWT_PUBLIC_KEY     path to a PEM public key -> only RS256 (RSA), ES256 (P-256) or EdDSA
                                  (Ed25519), whichever matches the key; needs ``cryptography``
                                  (python -m pip install "sf-smartwatch[jwt]")
and optionally SMARTWATCH_JWT_ISSUER and SMARTWATCH_JWT_AUDIENCE (checked when set).

A token is accepted when: it has three base64url parts; its header "alg" is the one the key allows
(never "none", no algorithm switching); the signature verifies; "exp" is a finite number in the future
but at most 24 hours ahead, and "nbf" (if present) in the past, with 60 s of leeway; "iss"/"aud" match when configured; and the scopes ("scope":
space-separated string, or "scp": list) include the one required. "sub" names who acted, in the audit log.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import time

LEEWAY_S = 60
MAX_LIFETIME_S = 86_400       # a token whose exp is further ahead than this is refused


class JWTError(ValueError):
    pass


def _num(v) -> bool:
    """A JSON number usable as a time: finite, and an integer no larger than 2^53 in magnitude."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return -2 ** 53 <= v <= 2 ** 53
    return isinstance(v, float) and math.isfinite(v)


def _b64d(s: str) -> bytes:
    if not isinstance(s, str) or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in s):
        raise JWTError('not base64url')
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


class JWTVerifier:
    def __init__(self, hs256_secret: bytes | None = None, public_key_pem: bytes | None = None,
                 issuer: str | None = None, audience: str | None = None, clock=time.time):
        if bool(hs256_secret) == bool(public_key_pem):
            raise ValueError('configure exactly one of an HS256 secret or a public key')
        self.issuer, self.audience, self.clock = issuer, audience, clock
        self.secret = None
        self.key = None
        if hs256_secret:
            if len(hs256_secret) < 32:
                raise ValueError('the HS256 secret must be at least 32 bytes')
            self.secret, self.alg = hs256_secret, 'HS256'
        else:
            try:
                from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
                from cryptography.hazmat.primitives.serialization import load_pem_public_key
            except ImportError:
                msg = 'a public key needs the cryptography package: python -m pip install "sf-smartwatch[jwt]"'
                raise ValueError(msg) from None
            k = load_pem_public_key(public_key_pem)
            if isinstance(k, rsa.RSAPublicKey):
                if k.key_size < 2048:
                    raise ValueError('RSA keys must be at least 2048 bits')
                self.alg = 'RS256'
            elif isinstance(k, ec.EllipticCurvePublicKey) and isinstance(k.curve, ec.SECP256R1):
                self.alg = 'ES256'
            elif isinstance(k, ed25519.Ed25519PublicKey):
                self.alg = 'EdDSA'
            else:
                raise ValueError('the public key must be RSA (2048+), EC P-256 or Ed25519')
            self.key = k

    def verify(self, token: str, scope: str) -> dict:
        """The claims, or JWTError."""
        if not isinstance(token, str) or token.count('.') != 2 or len(token) > 8192:
            raise JWTError('malformed token')
        h64, p64, s64 = token.split('.')
        try:
            header = json.loads(_b64d(h64))
            claims = json.loads(_b64d(p64))
            sig = _b64d(s64)
        except (ValueError, UnicodeDecodeError):
            raise JWTError('malformed token') from None
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise JWTError('malformed token')
        if header.get('alg') != self.alg or 'crit' in header:
            raise JWTError(f'algorithm must be {self.alg}')
        signing_input = (h64 + '.' + p64).encode('ascii')
        if not self._sig_ok(signing_input, sig):
            raise JWTError('bad signature')
        now = self.clock()
        exp = claims.get('exp')
        if not _num(exp) or now > exp + LEEWAY_S:
            raise JWTError('expired or no exp')
        if exp > now + MAX_LIFETIME_S + LEEWAY_S:
            raise JWTError('exp is more than 24 hours ahead: reset tokens must be short-lived')
        nbf = claims.get('nbf')
        if nbf is not None and (not _num(nbf) or now + LEEWAY_S < nbf):
            raise JWTError('not valid yet')
        if self.issuer is not None and claims.get('iss') != self.issuer:
            raise JWTError('wrong issuer')
        if self.audience is not None:
            aud = claims.get('aud')
            if not (aud == self.audience or (isinstance(aud, list) and self.audience in aud)):
                raise JWTError('wrong audience')
        scopes = set()
        if isinstance(claims.get('scope'), str):
            scopes |= set(claims['scope'].split())
        if isinstance(claims.get('scp'), list):
            scopes |= {s for s in claims['scp'] if isinstance(s, str)}
        if scope not in scopes:
            raise JWTError(f'scope {scope} missing')
        return claims

    def _sig_ok(self, data: bytes, sig: bytes) -> bool:
        if self.secret is not None:
            return hmac.compare_digest(hmac.new(self.secret, data, hashlib.sha256).digest(), sig)
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        try:
            if self.alg == 'RS256':
                self.key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
            elif self.alg == 'ES256':
                if len(sig) != 64:
                    return False
                der = encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big'))
                self.key.verify(der, data, ec.ECDSA(hashes.SHA256()))
            else:
                self.key.verify(sig, data)
            return True
        except (InvalidSignature, ValueError):
            return False


def make_hs256(secret: bytes, claims: dict) -> str:
    """For tests and the demo: sign claims with HS256."""
    h = b64e(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
    p = b64e(json.dumps(claims, separators=(',', ':')).encode())
    s = b64e(hmac.new(secret, (h + '.' + p).encode(), hashlib.sha256).digest())
    return f'{h}.{p}.{s}'
