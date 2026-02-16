"""
JWKS Server - Main Application
A RESTful server that provides JWT authentication and public key distribution.
"""

from flask import Flask, jsonify, request
from keys import KeyManager
import jwt
from datetime import datetime

app = Flask(__name__)
key_manager = KeyManager()


@app.route('/')
def index():
    """Root endpoint - provides server information"""
    return jsonify({
        "message": "JWKS Server",
        "endpoints": {
            "/auth": "POST - Get a signed JWT (use ?expired=true for expired token)",
            "/jwks": "GET - Retrieve public keys in JWKS format"
        }
    })


@app.route('/auth', methods=['POST'])
def auth():
    """
    Authentication endpoint.
    Returns a signed JWT. If 'expired' query parameter is present,
    returns a JWT signed with an expired key.
    """
    # Check if expired token is requested
    expired_requested = request.args.get('expired') == 'true'
    
    if expired_requested:
        # Get expired key
        key_data = key_manager.get_expired_key()
        if not key_data:
            return jsonify({"error": "No expired keys available"}), 500
    else:
        # Get valid key
        key_data = key_manager.get_valid_key()
        if not key_data:
            return jsonify({"error": "No valid keys available"}), 500
    
    # Create JWT payload
    payload = {
        "user": "testuser",
        "iat": datetime.utcnow(),
        "exp": key_data['expiry']
    }
    
    # Sign JWT with the private key
    token = jwt.encode(
        payload,
        key_data['private_key'],
        algorithm='RS256',
        headers={'kid': key_data['kid']}
    )
    
    return jsonify({"token": token})


@app.route('/jwks', methods=['GET'])
def jwks():
    """
    JWKS endpoint.
    Returns all valid (non-expired) public keys in JWKS format.
    """
    jwks_data = key_manager.get_jwks()
    return jsonify(jwks_data)


if __name__ == '__main__':
    print("Starting JWKS Server on port 8080...")
    print("Endpoints:")
    print("  POST http://localhost:8080/auth")
    print("  POST http://localhost:8080/auth?expired=true")
    print("  GET  http://localhost:8080/jwks")
    app.run(host='0.0.0.0', port=8080, debug=True)