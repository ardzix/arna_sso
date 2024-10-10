
# SSO Service

This project is an **SSO (Single Sign-On) service** built with Django. It handles authentication, JWT token management (with RS256 algorithm for token signing), and role-based access control (RBAC) for use across multiple microservices. The SSO service is designed to be integrated with other applications, using JWT tokens for user authentication and authorization.

## Table of Contents
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Key Configuration](#key-configuration)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Integration with Other Services](#integration-with-other-services)
- [License](#license)

## Features
- **JWT Authentication**: Secure authentication with JWT using the RS256 algorithm.
- **Role-based Access Control (RBAC)**: Assign roles and permissions to users, which control access to specific resources.
- **MFA (Multi-Factor Authentication)**: Users can enable MFA for added security.
- **JWT Token Rotation**: Support for token rotation and blacklisting of old tokens.
- **Audit Logging**: Logs key user actions like registration, login, and MFA setup.
- **Microservices Integration**: Easy integration with other services using JWT tokens.

## Technology Stack
- **Django**: Web framework for building the SSO service.
- **Django REST Framework**: Provides API endpoints for authentication and role management.
- **Django-Q2**: Used for asynchronous task processing and audit logging.
- **Simple JWT**: For managing JWT tokens with support for RS256 signing.
- **PyOTP**: For handling MFA using time-based one-time passwords (TOTP).

## Installation

### Prerequisites
- Python 3.8+
- Django 4.0+
- PostgreSQL or any other database supported by Django

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd sso_service
   ```

2. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run migrations**:
   ```bash
   python manage.py migrate
   ```

5. **Create superuser**:
   ```bash
   python manage.py createsuperuser
   ```

6. **Start the development server**:
   ```bash
   python manage.py runserver
   ```

### Key Generation for RS256

1. **Generate Private and Public Keys**:
   Run the following commands to generate the necessary keys for RS256:
   ```bash
   # Generate private key
   openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

   # Generate public key
   openssl rsa -pubout -in private.pem -out public.pem
   ```

2. **Move the keys to a secure location** and ensure they are properly referenced in the application configuration.

## Environment Variables

The project requires the following environment variables:

| Variable                  | Description                              |
|----------------------------|------------------------------------------|
| `SECRET_KEY`               | Django secret key for the application    |
| `DATABASE_URL`             | Database connection URL                  |
| `JWT_PRIVATE_KEY`          | Path to the private key for RS256 signing|
| `JWT_PUBLIC_KEY`           | Path to the public key for RS256 signing |

## Key Configuration

In your **`settings.py`**, configure JWT to use RS256 and your private key:

```python
from datetime import timedelta

with open('path/to/private.pem', 'r') as f:
    private_key = f.read()

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'ALGORITHM': 'RS256',
    'SIGNING_KEY': private_key,
}
```

## Usage

### 1. **User Registration**
   - A user can register by hitting the `/api/auth/register/` endpoint.
   - Once registered, the service issues an access token and a refresh token.

### 2. **User Login**
   - The `/api/auth/login/` endpoint will return JWT tokens (access and refresh).
   - If MFA is enabled for the user, a second step with an MFA token is required.

### 3. **Token Refresh**
   - The `/api/auth/refresh/` endpoint allows users to refresh their access tokens using the refresh token.

### 4. **Multi-Factor Authentication**
   - Users can enable MFA by hitting `/api/auth/set-mfa/`.
   - MFA-aware login is handled via `/api/auth/mfa-login/` and verified with `/api/auth/mfa-verify/`.

## API Endpoints

| Endpoint                    | Method | Description                                    |
|------------------------------|--------|------------------------------------------------|
| `/api/auth/register/`         | POST   | Register a new user                            |
| `/api/auth/login/`            | POST   | Log in a user and return JWT tokens            |
| `/api/auth/refresh/`          | POST   | Refresh the access token using a refresh token |
| `/api/auth/set-mfa/`          | POST   | Enable MFA for the user                        |
| `/api/auth/mfa-login/`        | POST   | MFA-aware login                                |
| `/api/auth/mfa-verify/`       | POST   | Verify MFA token and log in                    |
| `/api/auth/logout/`           | POST   | Log out and blacklist the refresh token        |

## Integration with Other Services

When integrating this SSO service with other microservices:

1. **Token Distribution**: After login, the SSO service issues JWT tokens (signed with RS256). The access token is used to authenticate subsequent requests.
   
2. **Public Key Distribution**: Distribute the **public key** (`public.pem`) to other services so they can validate JWT tokens issued by the SSO service.

3. **Role-Based Access Control**: Other services can decode the JWT token to verify user roles and permissions.

### Example Usage in Another Service:

- The JWT token is included in the `Authorization` header:
  ```http
  Authorization: Bearer <JWT-ACCESS-TOKEN>
  ```

- The other service decodes the token using the public key and checks the user’s roles and permissions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
