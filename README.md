# File Share

File Share is an OAuth-protected upload manager for GHWIZ.

- The configured management base path is the protected management UI.
- The configured management API path is the protected JSON/upload API.
- The configured share base path serves active shared files anonymously.

Uploaded bytes, share metadata, and generated thumbnails are stored in Postgres.
Image uploads can be re-encoded to strip metadata and optionally resized before
storage.
