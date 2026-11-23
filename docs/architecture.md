# Initial architecture

- `frontend/` is reserved for the frontend implementation.
- `backend/` contains the Node.js and TypeScript API, Prisma schema, migration,
  and synthetic seed script.
- PostgreSQL is the local development database and can be replaced with a
  Supabase PostgreSQL connection through environment variables.
- `docker-compose.yml` starts PostgreSQL and the backend API.

The API currently exposes only `GET /health`. Authentication and product
features are outside the scope of US-00.
