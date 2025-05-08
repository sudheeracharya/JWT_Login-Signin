# JWT Authentication API with Flask

This project implements a secure JWT (JSON Web Token) and API Key based authentication system using Python's Flask framework. The API includes user registration, login (via Basic Auth or JSON), and protected routes for users and admins.

## Features

- User Registration
- Login with JWT Token Generation
- JWT-Protected Routes
- API Key-Protected Routes
- Admin Routes for Viewing All Users
- Postman Integration for API Testing

---

## Technologies Used

- Python 3
- Flask
- Flask SQLAlchemy
- JWT (via `pyjwt`)
- SQLite (for development)
- Werkzeug Security (Password hashing)

---

## Getting Started

### Prerequisites

- Python 3 installed
- Postman for testing (optional but recommended)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/jwt-auth-api.git
   cd jwt-auth-api

Create a virtual environment:

bash
Copy
Edit
python -m venv venv
Activate the virtual environment:

On Windows:

bash
Copy
Edit
venv\Scripts\activate
On macOS/Linux:

bash
Copy
Edit
source venv/bin/activate
Install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Run the Flask app:

bash
Copy
Edit
python jwt_auth_api.py
The app should now be running at http://127.0.0.1:5000.

Using Postman with the JWT Auth API
1. Setting Up Postman
Requirements:

Postman installed

Flask app running with: python jwt_auth_api.py

Base URL: http://127.0.0.1:5000

2. Testing User Registration
Method: POST
URL: http://127.0.0.1:5000/signup

Headers:

Key: Content-Type

Value: application/json

Body (raw, JSON):

json
Copy
Edit
{
    "username": "testuser",
    "password": "testpassword"
}
Expected Response (201):

json
Copy
Edit
{
    "message": "User created successfully!",
    "api_key": "your-generated-api-key"
}
3. Testing Login (JWT Token Generation)
Option 1: Basic Auth Login
Method: POST
URL: http://127.0.0.1:5000/login

Auth: Basic Auth
Username: testuser
Password: testpassword

Expected Response:

json
Copy
Edit
{
    "token": "your-jwt-token",
    "api_key": "your-api-key"
}
Option 2: JSON Login
Method: POST
URL: http://127.0.0.1:5000/login/json

Headers:

Key: Content-Type

Value: application/json

Body (raw, JSON):

json
Copy
Edit
{
    "username": "testuser",
    "password": "testpassword"
}
Expected Response:

json
Copy
Edit
{
    "token": "your-jwt-token",
    "api_key": "your-api-key"
}
4. Testing JWT Protected Route
Method: GET
URL: http://127.0.0.1:5000/jwt/test

Headers:

Key: x-access-token

Value: your-jwt-token

Expected Response:

json
Copy
Edit
{
    "message": "Hello testuser! You accessed this endpoint using your JWT token."
}
5. Testing API Key Protected Route
Method: GET
URL: http://127.0.0.1:5000/api/test

Headers:

Key: x-api-key

Value: your-api-key

Expected Response:

json
Copy
Edit
{
    "message": "Hello testuser! You accessed this endpoint using your API key."
}
6. Testing Admin Routes
Login as Admin
Method: POST
URL: http://127.0.0.1:5000/login

Auth: Basic Auth
Username: admin
Password: admin

Save the admin JWT token from the response.

Get All Users (Admin Only)
Method: GET
URL: http://127.0.0.1:5000/admin/users

Headers:

Key: x-access-token

Value: admin-jwt-token

Expected Response:
List of registered users

7. Optional: Postman Collection Setup
Create a Postman Collection and save all the above requests.

Set environment variables in Postman:

base_url: http://127.0.0.1:5000

jwt_token

api_key

Use them in URLs and headers like:

{{base_url}}/signup

Header: x-access-token: {{jwt_token}}

Header: x-api-key: {{api_key}}

Requirements
Create a requirements.txt file for the dependencies:

ini
Copy
Edit
Flask==2.3.2
Flask-SQLAlchemy==3.1.1
PyJWT==2.8.0
Werkzeug==2.3.7

