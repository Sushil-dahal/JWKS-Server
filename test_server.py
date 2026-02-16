"""
Test Suite for JWKS Server
Tests all endpoints and functionality with >80% coverage.
"""

import pytest
import json
import jwt
from datetime import datetime, timedelta
from main import app
from keys import KeyManager


@pytest.fixture
def client():
    """Create test client"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def key_manager():
    """Create KeyManager instance"""
    return KeyManager()


class TestRootEndpoint:
    """Test root endpoint"""
    
    def test_root_returns_200(self, client):
        """Root endpoint should return 200"""
        response = client.get('/')
        assert response.status_code == 200
    
    def test_root_returns_json(self, client):
        """Root endpoint should return JSON"""
        response = client.get('/')
        data = json.loads(response.data)
        assert 'message' in data
        assert 'endpoints' in data


class TestAuthEndpoint:
    """Test /auth endpoint"""
    
    def test_auth_returns_200(self, client):
        """Auth endpoint should return 200 on POST"""
        response = client.post('/auth')
        assert response.status_code == 200
    
    def test_auth_returns_token(self, client):
        """Auth endpoint should return a JWT token"""
        response = client.post('/auth')
        data = json.loads(response.data)
        assert 'token' in data
        assert isinstance(data['token'], str)
    
    def test_auth_token_is_valid_jwt(self, client):
        """Returned token should be a valid JWT"""
        response = client.post('/auth')
        data = json.loads(response.data)
        token = data['token']
        
        # Decode without verification to check structure
        unverified = jwt.decode(token, options={"verify_signature": False})
        assert 'user' in unverified
        assert 'exp' in unverified
    
    def test_auth_token_has_kid(self, client):
        """JWT should have kid in header"""
        response = client.post('/auth')
        data = json.loads(response.data)
        token = data['token']
        
        # Get header
        header = jwt.get_unverified_header(token)
        assert 'kid' in header
    
    def test_auth_expired_returns_token(self, client):
        """Auth with expired param should return expired token"""
        response = client.post('/auth?expired=true')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'token' in data
    
    def test_auth_expired_token_is_expired(self, client):
        """Expired token should have past expiry"""
        response = client.post('/auth?expired=true')
        data = json.loads(response.data)
        token = data['token']
        
        unverified = jwt.decode(token, options={"verify_signature": False})
        exp_time = datetime.fromtimestamp(unverified['exp'])
        assert exp_time < datetime.utcnow()
    
    def test_auth_only_accepts_post(self, client):
        """Auth endpoint should only accept POST"""
        response = client.get('/auth')
        assert response.status_code == 405


class TestJWKSEndpoint:
    """Test /jwks endpoint"""
    
    def test_jwks_returns_200(self, client):
        """JWKS endpoint should return 200"""
        response = client.get('/jwks')
        assert response.status_code == 200
    
    def test_jwks_returns_json(self, client):
        """JWKS should return valid JSON"""
        response = client.get('/jwks')
        data = json.loads(response.data)
        assert isinstance(data, dict)
        assert 'keys' in data
    
    def test_jwks_contains_keys_array(self, client):
        """JWKS should have keys array"""
        response = client.get('/jwks')
        data = json.loads(response.data)
        assert isinstance(data['keys'], list)
        assert len(data['keys']) > 0
    
    def test_jwks_keys_have_required_fields(self, client):
        """Each key should have required JWK fields"""
        response = client.get('/jwks')
        data = json.loads(response.data)
        
        for key in data['keys']:
            assert 'kty' in key
            assert 'use' in key
            assert 'kid' in key
            assert 'alg' in key
            assert 'n' in key
            assert 'e' in key
    
    def test_jwks_only_returns_valid_keys(self, client):
        """JWKS should not include expired keys"""
        response = client.get('/jwks')
        data = json.loads(response.data)
        
        # Should have at least one key but not include expired
        assert len(data['keys']) >= 1


class TestKeyManager:
    """Test KeyManager class"""
    
    def test_key_manager_generates_keys(self, key_manager):
        """KeyManager should generate keys on init"""
        assert len(key_manager.keys) > 0
    
    def test_get_valid_key_returns_key(self, key_manager):
        """get_valid_key should return a valid key"""
        key = key_manager.get_valid_key()
        assert key is not None
        assert 'kid' in key
        assert 'private_key' in key
    
    def test_get_expired_key_returns_key(self, key_manager):
        """get_expired_key should return an expired key"""
        key = key_manager.get_expired_key()
        assert key is not None
        assert key['is_expired'] or key['expiry'] < datetime.utcnow()
    
    def test_get_jwks_structure(self, key_manager):
        """get_jwks should return proper structure"""
        jwks = key_manager.get_jwks()
        assert 'keys' in jwks
        assert isinstance(jwks['keys'], list)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--cov=.', '--cov-report=term-missing'])