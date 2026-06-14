# File Share

File Share is an OAuth-protected upload manager.

- The configured management base path is the protected management UI.
- The configured management API path is the protected JSON/upload API.
- The configured share base path serves active shared files anonymously.
- The management base path opens the phone-first upload page by default.
- The management grid lives at `<management-base>/manage` and groups compact
  preview tiles by active links expiring soon, other active links, and hidden
  expired/revoked links. File details and CRUD actions live in the tile modal.

Uploaded bytes, share metadata, and generated thumbnails are stored in Postgres.
Image uploads can be re-encoded to strip metadata and optionally resized before
storage.

Generated anonymous share names use eight hexadecimal characters plus the stored
file extension. The app checks for an existing token across extensions before it
allocates a new share name.
