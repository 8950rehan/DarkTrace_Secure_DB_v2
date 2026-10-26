# DarkTrace Secure Database v2

Beginner-friendly PostgreSQL schema and a small FastAPI example for the DarkTrace monitoring database. It extends the original `users → source → crawl_job` design with a normalized `authorizations` table and an `audit_log`, while adding validation, foreign keys, check constraints, and useful indexes.

## Structure

- `users`: accounts, Argon2 password hash, constrained roles/status.
- `authorizations`: approval reference, approving user, purpose, validity window and revocation status.
- `source`: monitored-source registry; every source must reference a valid authorization and creator.
- `crawl_job`: source/job lifecycle and the user who requested it.
- `audit_log`: actor-attributed event history without secrets.
- `app/main.py`: FastAPI examples with Pydantic validation and parameterized SQL.
- `schema.sql`: PostgreSQL DDL and optional least-privilege role grants.

## Run locally

1. Create a PostgreSQL database (PostgreSQL 14+ recommended).
2. Apply the schema as a database owner/migration user:

   ```bash
   psql "$DATABASE_URL" -f schema.sql
   ```

3. Create a virtual environment and install dependencies:

   ```bash
   python -m venv .venv
   # Windows: .venv\Scripts\activate
   # Linux/macOS: source .venv/bin/activate
   pip install -r requirements.txt
   ```

4. Set `DATABASE_URL` in your terminal or deployment environment. Do not commit `.env` or real credentials.
5. Start the API:

   ```bash
   uvicorn app.main:app --reload
   ```

6. Open `http://127.0.0.1:8000/docs` to try the API.

## Security choices

- Passwords are hashed with Argon2 (never stored as plaintext).
- User input is validated with Pydantic and database constraints.
- SQL uses `%s` parameters; input is never concatenated into query strings.
- `authorizations` are normalized to avoid repeated authorization data and each source/job checks authorization status and expiry.
- Foreign keys protect referential integrity; `CHECK` constraints restrict roles, states, and types.
- Audit events avoid password/token values.
- Use TLS (`sslmode=require` or provider-specific SSL settings), environment-managed secrets, least-privilege database credentials, backups, and regular dependency updates.

## Important production notes

This is an educational starter, not a complete production authentication system. Before deployment, add authentication/session or JWT verification, enforce authorization per endpoint (the sample accepts UUIDs directly and must not be exposed as-is to the public internet), rate limiting, CSRF protection if cookie-based auth is used, request-size limits, centralized safe logging, and tests. The example does not implement login or password verification endpoints. Keep crawler workers isolated and do not give them broad database permissions.

## GitHub / Railway

- Upload the folder contents to a new GitHub repository.
- In Railway, create a PostgreSQL service and a Python service connected to that repo.
- Set `DATABASE_URL` from the Railway PostgreSQL service in the Python service variables.
- Ensure the schema is applied as a migration step (do not assume Railway automatically runs `schema.sql`). Set the start command to `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
- For production, use a migration tool such as Alembic and a dedicated migration role.
