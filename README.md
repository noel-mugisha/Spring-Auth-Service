# Enterprise Spring Boot Authentication Service

[![Java](https://img.shields.io/badge/Java-21-orange?style=flat-square&logo=java)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.8-6DB33F?style=flat-square&logo=spring-boot&logoColor=white)](https://spring.io/projects/spring-boot)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Flyway](https://img.shields.io/badge/Flyway-10.x-A41E11?style=flat-square&logo=flyway&logoColor=white)](https://flywaydb.org/)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3-6BA539?style=flat-square&logo=openapi-initiative&logoColor=white)](https://swagger.io/specification/)
[![Google OAuth2](https://img.shields.io/badge/Google%20OAuth2-4285F4?style=flat-square&logo=google&logoColor=white)](https://developers.google.com/identity/protocols/oauth2)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

A comprehensive, production-ready authentication and user management service built with Spring Boot. This service provides robust security features including JWT-based authentication, refresh token rotation with HttpOnly cookies, OAuth2 social login (Google), email verification with OTP, password reset workflows, rate limiting, and database migrations. Designed for modern web applications requiring secure, scalable user authentication and authorization.

---

## Highlights ✨

- **Multi-Authentication Support**: JWT-based authentication with OAuth2 social login (Google)
- **Secure Token Management**: Refresh token rotation with one-time use and server-side revocation
- **Stateless APIs**: Short-lived JWT access tokens (15 min) with HttpOnly, Secure cookies for refresh tokens (XSS-safe)
- **Hashed Token Storage**: SHA-256 hashed refresh tokens stored securely in database
- **Rate Limiting**: Bucket4j-based rate limiting on authentication endpoints (10 requests/min per IP)
- **Email Workflows**: Event-driven email OTP registration and password reset with secure links
- **Role-Based Access Control**: RBAC with method-level security using @PreAuthorize annotations
- **Database Migrations**: Versioned schema management with Flyway
- **API Documentation**: OpenAPI/Swagger UI integration out of the box
- **Social Authentication**: Seamless OAuth2 integration allowing users to authenticate via Google accounts

---

## Architecture & Tech Stack 🧩

- **Language**: Java 21
- **Framework**: Spring Boot 3.5.x, Spring Web, Spring Security, Spring OAuth2 Client
- **Database**: PostgreSQL 16
- **Migrations**: Flyway 10.x
- **JWT**: JJWT 0.12.x
- **Rate Limiting**: Bucket4j
- **Mapping/Boilerplate**: MapStruct, Lombok
- **API Docs**: springdoc-openapi
- **OAuth2**: Spring Security OAuth2 Client for social authentication

---

## API Surface 🔗

### Authentication Endpoints

**Public Endpoints**
- `POST /api/v1/auth/send-otp` — Send registration OTP to email
- `POST /api/v1/auth/verify-otp` — Verify OTP; returns a temporary preAuth token
- `POST /api/v1/auth/register` — Complete registration; requires `Authorization: Bearer <preAuth-token>`
- `POST /api/v1/auth/login` — Traditional login; returns access token (JSON) and sets refresh token cookie
- `POST /api/v1/auth/refresh` — Rotate refresh token and return new access token
- `POST /api/v1/auth/logout` — Revoke refresh token and clear cookie
- `POST /api/v1/auth/forgot-password` — Request password reset link
- `POST /api/v1/auth/reset-password` — Reset password using token

**OAuth2 Endpoints**
- `GET /oauth2/authorization/google` — Initiate Google OAuth2 login flow
- `GET /login/oauth2/code/google` — OAuth2 callback endpoint (handled internally)

**Protected Endpoints**
- `GET /api/v1/users/me` — Get current user profile
- `GET /api/v1/users` — List all users (ADMIN role required)

### API Documentation
- **Swagger UI**: http://localhost:8080/swagger-ui.html
- **OpenAPI JSON**: http://localhost:8080/v3/api-docs

### Authentication Flows

**Traditional Registration Flow**
1. Send OTP → Verify OTP → Receive preAuth token → Register with preAuth token → Receive access token + refresh cookie

**OAuth2 Login Flow**
1. Redirect to `/oauth2/authorization/google` → User authenticates with Google → Redirect back with authorization code → Service processes user info → Set refresh token cookie → Redirect to frontend dashboard

**Token Management**
- Access tokens are JWTs valid for 15 minutes
- Refresh tokens are HttpOnly cookies valid for 7 days
- Refresh endpoint rotates tokens for enhanced security

---

## Setup ⚙️

Prerequisites
- Java 21
- Maven 3.9+
- PostgreSQL 14+

### Environment Configuration

Create a `.env` file in the project root (or export environment variables) with the following keys:

```properties
# Database Configuration
DB_URL=jdbc:postgresql://localhost:5432/auth_db
DB_USERNAME=postgres
DB_PASSWORD=your_secure_password

# JWT Configuration (use a strong, base64-encoded 256-bit key)
JWT_SECRET_KEY=your_very_long_random_secret_key_base64_encoded

# Email Configuration (SMTP)
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password

# Frontend Configuration
FRONTEND_URL=http://localhost:3000

# OAuth2 Configuration (Google)
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
```

### OAuth2 Setup

To enable Google OAuth2 authentication:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Create OAuth 2.0 credentials (Client ID and Client Secret)
5. Add your frontend URL to authorized redirect URIs
6. Set the redirect URI to: `{your-frontend-url}/login/oauth2/code/google`
7. Add the Client ID and Client Secret to your `.env` file

Run
- Windows: mvnw.cmd spring-boot:run
- Linux/Mac: ./mvnw spring-boot:run

The application starts on port 8080.

Database migrations run automatically via Flyway on startup.

---

## Security Model 🔐

### Authentication Methods

- **JWT Authentication**: Traditional email/password with OTP verification
- **OAuth2 Social Login**: Google OAuth2 integration for seamless authentication
- **Hybrid Support**: Users can link OAuth2 accounts to existing profiles or create new accounts via social login

### Token Security

- **Access Tokens**: JWT tokens in `Authorization: Bearer <token>` header, expires in 15 minutes
- **Refresh Tokens**: HttpOnly, Secure cookies containing opaque UUIDs, stored as SHA-256 hashes in database
- **Token Rotation**: Each `/refresh` call invalidates the previous refresh token and issues a new one
- **Cookie Security**: Refresh tokens use `HttpOnly`, `Secure`, and appropriate `SameSite` attributes

### Protection Mechanisms

- **Rate Limiting**: 10 requests per minute per IP on authentication endpoints using Bucket4j
- **CORS Configuration**: Configurable allowed origins via `FRONTEND_URL` environment variable
- **Pre-registration Security**: Short-lived preAuth tokens (10 minutes) for secure registration completion
- **Open Redirect Protection**: OAuth2 redirects validated against configured frontend URL

### OAuth2 Security Features

- **State Parameter**: Prevents CSRF attacks during OAuth2 flow
- **PKCE Support**: Proof Key for Code Exchange for enhanced security
- **Secure Redirects**: Only allows redirects to pre-configured frontend URLs
- **User Info Validation**: Email verification required from OAuth2 providers

---

## Admin Seeder 🧑‍💻

An optional admin seeder can bootstrap an admin account on startup (controlled via application.yaml):
- Email: admin@company.com
- Password: ChangeMe123! (change immediately or disable seeding)

---

## Development & Testing 🧪

- Build: mvnw.cmd -q -DskipTests package (Windows) or ./mvnw -q -DskipTests package
- Tests: mvnw.cmd test or ./mvnw test

---

## Contributing 🤝

We welcome contributions that improve stability, performance, security, or developer experience.

- Getting started
  - Fork the repository and create a feature branch from main.
  - Use Java 21 and Maven 3.9+.
  - Run ./mvnw test to ensure the test suite passes before committing.

- Development standards
  - Follow idiomatic Spring Boot patterns and keep services/interface contracts clean.
  - Keep security-sensitive changes small and well-documented in PR descriptions.
  - Prefer MapStruct for mappings and avoid manual boilerplate when possible.
  - Format code with the default IntelliJ Java style and organize imports.

- Commits & PRs
  - Use conventional commit messages (e.g., feat:, fix:, docs:, refactor:, test:).
  - Open focused PRs with a clear description, screenshots/logs when relevant, and test coverage.
  - Link related issues and update README or OpenAPI docs when behavior changes.

- Security
  - Do not open public issues for vulnerabilities. Instead, email the maintainer listed in OpenApiConfig (Contact) with details and a minimal reproduction. We will coordinate a responsible disclosure process.

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## Contact 📬

For more information or inquiries, please reach out at: noelmugisha332@gmail.com

---

## License

This project is licensed under the MIT License — see the LICENSE file for details.
