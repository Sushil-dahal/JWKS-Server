"""
Key Management Module
Handles RSA key generation, storage, and JWKS format conversion.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import base64
import uuid


class KeyManager:
    """Manages RSA key pairs with expiry timestamps and kid identifiers"""
    
    def __init__(self):
        self.keys = []
        self._generate_keys()
    
    def _generate_keys(self):
        """Generate both valid and expired RSA key pairs"""
        # Generate a valid key (expires in 1 hour)
        valid_key = self._create_key_pair(expiry_hours=1)
        self.keys.append(valid_key)
        
        # Generate an expired key (expired 1 hour ago)
        expired_key = self._create_key_pair(expiry_hours=-1)
        self.keys.append(expired_key)
    
    def _create_key_pair(self, expiry_hours=1):
        """
        Create an RSA key pair with associated metadata.
        
        Args:
            expiry_hours: Hours until expiry (negative for expired keys)
        
        Returns:
            dict: Key pair with metadata
        """
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Calculate expiry time
        expiry = datetime.utcnow() + timedelta(hours=expiry_hours)
        
        # Generate unique kid
        kid = str(uuid.uuid4())
        
        return {
            'kid': kid,
            'private_key': private_pem,
            'public_key': public_key,
            'expiry': expiry,
            'is_expired': expiry < datetime.utcnow()
        }
    
    def get_valid_key(self):
        """Get a non-expired key"""
        for key in self.keys:
            if not key['is_expired'] and key['expiry'] > datetime.utcnow():
                return key
        return None
    
    def get_expired_key(self):
        """Get an expired key"""
        for key in self.keys:
            if key['is_expired'] or key['expiry'] < datetime.utcnow():
                return key
        return None
    
    def get_jwks(self):
        """
        Get JWKS (JSON Web Key Set) containing only valid keys.
        
        Returns:
            dict: JWKS format with valid public keys
        """
        jwks_keys = []
        
        for key in self.keys:
            # Only include non-expired keys in JWKS
            if not key['is_expired'] and key['expiry'] > datetime.utcnow():
                jwk = self._public_key_to_jwk(key['public_key'], key['kid'])
                jwks_keys.append(jwk)
        
        return {"keys": jwks_keys}
    
    def _public_key_to_jwk(self, public_key, kid):
        """
        Convert a public key to JWK format.
        
        Args:
            public_key: RSA public key object
            kid: Key ID
        
        Returns:
            dict: JWK representation
        """
        # Get public numbers
        public_numbers = public_key.public_numbers()
        
        # Convert to base64url format (RFC 7517)
        n = self._int_to_base64url(public_numbers.n)
        e = self._int_to_base64url(public_numbers.e)
        
        return {
            "kty": "RSA",
            "use": "sig",
            "kid": kid,
            "alg": "RS256",
            "n": n,
            "e": e
        }
    
    def _int_to_base64url(self, value):
        """Convert integer to base64url-encoded string"""
        # Convert int to bytes
        value_bytes = value.to_bytes(
            (value.bit_length() + 7) // 8, 
            byteorder='big'
        )
        # Encode to base64url
        encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
        return encoded.decode('utf-8')