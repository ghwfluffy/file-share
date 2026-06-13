# Agent Instructions

- This app is OAuth-only. Do not add local password, registration, or bootstrap auth.
- Keep the configured management prefix as the protected surface and the configured share prefix as the anonymous shared-file surface. Production prefixes are owned by the omnisite root repo.
- Store uploaded files in Postgres, not in the container filesystem.
- Keep shared URLs unguessable and revocable. Treat anyone with a live configured share URL as authorized to fetch that one file.
- Run `api/lint.sh` and `api/test.sh` after backend changes.
