import os
import datetime
import uuid
from functools import wraps

from flask import Flask, request, jsonify, make_response
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# Initialize Flask application
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Better to use env var in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    api_key = db.Column(db.String(100), unique=True)
    admin = db.Column(db.Boolean, default=False)

# Create database tables within application context
with app.app_context():
    db.create_all()

# Decorator for JWT token verification
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if token is in headers
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        # Return 401 if token is missing
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Decode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
        
        # Pass the current user to the route
        return f(current_user, *args, **kwargs)
    
    return decorated

# Decorator for API key verification
def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = None
        
        # Check if API key is in headers
        if 'x-api-key' in request.headers:
            api_key = request.headers['x-api-key']
        
        # Return 401 if API key is missing
        if not api_key:
            return jsonify({'message': 'API key is missing!'}), 401
        
        # Find user with the given API key
        current_user = User.query.filter_by(api_key=api_key).first()
        
        if not current_user:
            return jsonify({'message': 'Invalid API key!'}), 401
        
        # Pass the current user to the route
        return f(current_user, *args, **kwargs)
    
    return decorated

# User registration route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    # Check if username and password are provided
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password!'}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists!'}), 409
    
    # Hash the password
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    # Generate API key
    api_key = str(uuid.uuid4())
    
    # Create new user
    new_user = User(
        public_id=str(uuid.uuid4()),
        username=data['username'],
        password=hashed_password,
        api_key=api_key,
        admin=False
    )
    
    # Add user to database
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({
        'message': 'User created successfully!',
        'api_key': api_key
    }), 201

# User login route
@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    
    # Check if authorization header is provided
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    # Find user by username
    user = User.query.filter_by(username=auth.username).first()
    
    # Check if user exists and password is correct
    if not user or not check_password_hash(user.password, auth.password):
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    # Generate JWT token
    token = jwt.encode({
        'public_id': user.public_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'token': token,
        'api_key': user.api_key
    })

# Alternative login with JSON payload
@app.route('/login/json', methods=['POST'])
def login_json():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password!'}), 400
    
    # Find user by username
    user = User.query.filter_by(username=data['username']).first()
    
    # Check if user exists and password is correct
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials!'}), 401
    
    # Generate JWT token
    token = jwt.encode({
        'public_id': user.public_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'token': token,
        'api_key': user.api_key
    })

# API key authentication test route
@app.route('/api/test', methods=['GET'])
@api_key_required
def api_test(current_user):
    return jsonify({
        'message': f'Hello {current_user.username}! You accessed this endpoint using your API key.'
    })

# JWT token authentication test route
@app.route('/jwt/test', methods=['GET'])
@token_required
def jwt_test(current_user):
    return jsonify({
        'message': f'Hello {current_user.username}! You accessed this endpoint using your JWT token.'
    })

# Get all users route (admin only)
@app.route('/admin/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    # Check if user is admin
    if not current_user.admin:
        return jsonify({'message': 'Permission denied!'}), 403
    
    users = User.query.all()
    
    output = []
    for user in users:
        user_data = {
            'public_id': user.public_id,
            'username': user.username,
            'admin': user.admin
        }
        output.append(user_data)
    
    return jsonify({'users': output})

# Promote user to admin (admin only)
@app.route('/admin/promote/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    # Check if user is admin
    if not current_user.admin:
        return jsonify({'message': 'Permission denied!'}), 403
    
    user = User.query.filter_by(public_id=public_id).first()
    
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    
    user.admin = True
    db.session.commit()
    
    return jsonify({'message': 'User has been promoted to admin!'})

# Create first admin user if database is empty
def create_admin_if_empty():
    with app.app_context():
        if User.query.count() == 0:
            admin_password = generate_password_hash('admin', method='pbkdf2:sha256')
            admin_user = User(
                public_id=str(uuid.uuid4()),
                username='admin',
                password=admin_password,
                api_key=str(uuid.uuid4()),
                admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print(f"Created admin user with username: 'admin' and password: 'admin'")
            print(f"API Key: {admin_user.api_key}")

# Run the application
if __name__ == '__main__':
    create_admin_if_empty()
    app.run(debug=True)