# Enterprise Spring Boot Authentication Service

[![Java](https://img.shields.io/badge/Java-21-orange?style=flat-square&logo=java)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.8-6DB33F?style=flat-square&logo=spring-boot&logoColor=white)](https://spring.io/projects/spring-boot)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Flyway](https://img.shields.io/badge/Flyway-10.x-A41E11?style=flat-square&logo=flyway&logoColor=white)](https://flywaydb.org/)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3-6BA539?style=flat-square&logo=openapi-initiative&logoColor=white)](https://swagger.io/specification/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

A production-ready authentication and user management service for modern backends. It implements secure, scalable patterns including refresh token rotation via HttpOnly cookies, rate limiting, event-driven email workflows, and database migrations.

---

## Highlights ✨

- Refresh Token Rotation with one-time use and server-side revocation
- Short-lived JWT Access Tokens (15 min) and stateless APIs
- HttpOnly, Secure cookies for refresh tokens (XSS-safe)
- Hashed (SHA-256) refresh tokens stored in DB
- Rate limiting on authentication endpoints (Bucket4j)
- Event-driven email OTP registration and password reset
- RBAC with method-level security (@PreAuthorize)
- Versioned schema management with Flyway
- OpenAPI/Swagger UI out of the box

---

## Architecture & Tech Stack 🧩

- Language: Java 21
- Framework: Spring Boot 3.5.x, Spring Web, Spring Security
- Database: PostgreSQL
- Migrations: Flyway
- JWT: JJWT 0.12.x
- Rate Limiting: Bucket4j
- Mapping/Boilerplate: MapStruct, Lombok
- API Docs: springdoc-openapi

---

## API Surface 🔗

Public
- POST /api/v1/auth/send-otp — send registration OTP to email
- POST /api/v1/auth/verify-otp — verify OTP; returns a temporary preAuth token
- POST /api/v1/auth/register — complete registration; requires `Authorization: Bearer <preAuth-token>`
- POST /api/v1/auth/login — login; returns access token (JSON) and sets refresh token cookie
- POST /api/v1/auth/refresh — rotate refresh token and return new access token
- POST /api/v1/auth/logout — revoke refresh token and clear cookie
- POST /api/v1/auth/forgot-password — request password reset link
- POST /api/v1/auth/reset-password — reset password using token

Protected
- GET /api/v1/users/me — current user profile
- GET /api/v1/users — list users (ADMIN only)

OpenAPI
- UI: http://localhost:8080/swagger-ui.html
- JSON: http://localhost:8080/v3/api-docs

Registration flow (summary)
- Send OTP → Verify OTP → Receive preAuth token → Call Register with `Authorization: Bearer <preAuth-token>` → Receive access token + refresh cookie

---

## Setup ⚙️

Prerequisites
- Java 21
- Maven 3.9+
- PostgreSQL 14+

Environment
Create a .env file (or export environment variables) with the following keys:

```properties
# Database
DB_URL=jdbc:postgresql://localhost:5432/auth_db
DB_USERNAME=postgres
DB_PASSWORD=your_secure_password

# JWT (use a strong, base64-encoded 256-bit key)
JWT_SECRET_KEY=your_very_long_random_secret_key_base64_encoded

# Email (SMTP)
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password

# Client
FRONTEND_URL=http://localhost:3000
```

Run
- Windows: mvnw.cmd spring-boot:run
- Linux/Mac: ./mvnw spring-boot:run

The application starts on port 8080.

Database migrations run automatically via Flyway on startup.

---

## Security Model (at a glance) 🔐

- Access token: JWT in Authorization: Bearer <token>, expires ~15 minutes
- Refresh token: HttpOnly, Secure cookie; opaque UUID stored as SHA-256 hash in DB
- Rotation: each /refresh call invalidates previous token and issues a new one
- Rate limiting: 10 requests/minute per IP on /api/v1/auth/**
- CORS: allowed origins configured via FRONTEND_URL

Additional details
- Pre-registration security: a short-lived preAuth registration token (issued by `verify-otp`) is recognized by the JWT filter and allowed only for completing `/auth/register`. It cannot access protected resources.
- Cookie name: refresh token is set as `refresh_token` with HttpOnly, Secure, SameSite attributes appropriate for cross-site usage with CORS.

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
