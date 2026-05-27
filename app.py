"""
REST API application with user registration endpoint.
Implements security best practices for authentication and user management.
"""

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from marshmallow import Schema, fields, ValidationError, validate
import bcrypt
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 
    'sqlite:///users.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_SORT_KEYS'] = False

# Initialize extensions
db = SQLAlchemy(app)
CORS(app, resources={r"/api/*": {"origins": "*"}})


# ============================================================================
# Database Models
# ============================================================================

class User(db.Model):
    """User model for storing user registration data."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(120))
    last_name = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        """Hash and set password using bcrypt."""
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'), 
            bcrypt.gensalt(rounds=12)
        ).decode('utf-8')
    
    def check_password(self, password):
        """Verify password against stored hash."""
        return bcrypt.checkpw(
            password.encode('utf-8'), 
            self.password_hash.encode('utf-8')
        )
    
    def to_dict(self):
        """Convert user object to dictionary (excludes password)."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'created_at': self.created_at.isoformat(),
            'is_active': self.is_active
        }


# ============================================================================
# Validation Schemas
# ============================================================================

class UserRegistrationSchema(Schema):
    """Schema for validating user registration input."""
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=80, error="Username must be 3-80 characters"),
            validate.Regexp(
                r'^[a-zA-Z0-9_-]+$',
                error="Username can only contain letters, numbers, underscore, and hyphen"
            )
        ]
    )
    email = fields.Email(required=True)
    password = fields.Str(
        required=True,
        validate=validate.Length(
            min=8,
            error="Password must be at least 8 characters"
        )
    )
    first_name = fields.Str(validate=validate.Length(max=120), allow_none=True)
    last_name = fields.Str(validate=validate.Length(max=120), allow_none=True)


# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(400)
def bad_request(error):
    """Handle bad request errors."""
    return jsonify({'error': 'Bad request', 'message': str(error)}), 400


@app.errorhandler(404)
def not_found(error):
    """Handle not found errors."""
    return jsonify({'error': 'Not found', 'message': str(error)}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    db.session.rollback()
    return jsonify({'error': 'Internal server error', 'message': str(error)}), 500


# ============================================================================
# API Routes
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200


@app.route('/api/auth/register', methods=['POST'])
def register_user():
    """
    User registration endpoint.
    
    Expected JSON payload:
    {
        "username": "john_doe",
        "email": "john@example.com",
        "password": "secure_password_123",
        "first_name": "John",
        "last_name": "Doe"
    }
    
    Returns:
        - 201: User successfully created
        - 400: Validation error or duplicate user
        - 500: Server error
    """
    try:
        # Validate JSON content type
        if not request.is_json:
            return jsonify({
                'error': 'Invalid content type',
                'message': 'Content-Type must be application/json'
            }), 400
        
        # Get JSON data
        data = request.get_json()
        
        # Validate input data
        schema = UserRegistrationSchema()
        try:
            validated_data = schema.load(data)
        except ValidationError as err:
            return jsonify({
                'error': 'Validation error',
                'details': err.messages
            }), 400
        
        # Check if user already exists
        existing_user = User.query.filter(
            db.or_(
                User.username == validated_data['username'],
                User.email == validated_data['email']
            )
        ).first()
        
        if existing_user:
            if existing_user.username == validated_data['username']:
                return jsonify({
                    'error': 'User already exists',
                    'message': 'Username is already taken'
                }), 400
            else:
                return jsonify({
                    'error': 'User already exists',
                    'message': 'Email is already registered'
                }), 400
        
        # Create new user
        new_user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data.get('first_name'),
            last_name=validated_data.get('last_name')
        )
        
        # Set password (hashed)
        new_user.set_password(validated_data['password'])
        
        # Save to database
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'message': 'User registered successfully',
            'user': new_user.to_dict()
        }), 201
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({
            'error': 'Registration failed',
            'message': 'An unexpected error occurred'
        }), 500


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get user details by ID (excludes password)."""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({
            'error': 'Not found',
            'message': f'User with ID {user_id} not found'
        }), 404
    
    return jsonify(user.to_dict()), 200


# ============================================================================
# Application Initialization
# ============================================================================

def init_db():
    """Initialize database with tables."""
    with app.app_context():
        db.create_all()
        print("Database initialized successfully")


if __name__ == '__main__':
    # Initialize database on startup
    init_db()
    
    # Run development server
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_ENV') == 'development'
    )
