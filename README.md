# School Portal

Flask application with JWT authentication and SQLite persistence.

## Run with Docker Compose

1. Copy `.env.example` to `.env`.
2. Set `FLAG` in `.env`.
3. Start the portal:

   ```sh
   docker compose up --build -d
   ```

The portal listens on `http://localhost:8080` by default. Change `PORT` in `.env` to use a different host port. Stop it with `docker compose down`.

The seeded student account is `student` / `student123`. SQLite data is kept in the `portal_data` Docker volume. To remove the database and start fresh, use `docker compose down -v`.
