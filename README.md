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
## Create a Virtual Environment and Activate It:

1. **Create a virtual environment**:

   ```bash
   python -m venv venv
   ```

2. **Activate the virtual environment**:

   - On **Windows**:
     ```bash
     venv\Scripts\activate
     ```

   - On **macOS/Linux**:
     ```bash
     source venv/bin/activate
     ```

## Install Dependencies:

```bash
pip install -r requirements.txt
```

## Run the Flask App:

```bash
python jwt_auth_api.py
```

The app should now be running at [http://127.0.0.1:5000](http://127.0.0.1:5000).

## Using Postman with the JWT Auth API

You can use Postman to interact with the API. Below are the steps for testing the endpoints.

1. **Register a new user** (POST request to `/register`).
2. **Login to receive a JWT token** (POST request to `/login`).
3. **Use the received JWT token to access protected routes**.
4. **Admin route for viewing all users** (GET request to `/admin/users`).

### Example Usage

1. **Register a user:**

   ```bash
   curl -X POST -H "Content-Type: application/json" -d '{"username": "testuser", "password": "testpassword"}' http://127.0.0.1:5000/register
   ```

2. **Login with credentials:**

   ```bash
   curl -X POST -H "Content-Type: application/json" -d '{"username": "testuser", "password": "testpassword"}' http://127.0.0.1:5000/login
   ```

3. **Access a protected route:**

   ```bash
   curl -X GET -H "Authorization: Bearer <your-jwt-token>" http://127.0.0.1:5000/protected
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
