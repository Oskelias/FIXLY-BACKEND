# Cloudflare bindings & variables

## Required bindings

### D1
Create a D1 database and bind it as `DB`:

```toml
[[d1_databases]]
binding = "DB"
database_name = "fixly-taller-db"
database_id = "<your-db-id>"
```

### R2 (backups)
Create an R2 bucket and bind it as `BACKUPS`:

```toml
[[r2_buckets]]
binding = "BACKUPS"
bucket_name = "fixly-backups"
```

## Required secrets (set via `wrangler secret put`)

```
JWT_SECRET
MASTER_KEY
```

## Optional vars

```
ADMIN_DOMAIN=https://admin.fixlytaller.com
APP_DOMAIN=https://app.fixlytaller.com
CORS_ALLOWED=https://app.fixlytaller.com,https://admin.fixlytaller.com
```

## Notes
- The backup endpoints expect the `BACKUPS` binding to exist.
- Location-aware endpoints require `X-Location-Id` (or `locationId` query param/body).
