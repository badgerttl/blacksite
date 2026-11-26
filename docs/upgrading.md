# Upgrading Blacksite

`./blacksite build` and `./blacksite up` pull the configured application images,
pull updated Dockerfile base images, and invalidate the Git checkout and Cargo
installation layers. RevShell and HackTricks default to upstream `HEAD`. Ollama
is included in the image refresh when `--local-llm` is supplied.

`build` prepares images without restarting applications. `up` applies the images
and runs the Hoppscotch migration and Open WebUI tool deployment services.

Application images track `latest`. PostgreSQL tracks `19-alpine`, the current
major version, so a future major release cannot silently replace the database
engine. Changes to the database major version need another explicit migration.

## Back up before updating

Stop Hoppscotch, CloudBeaver, and Open WebUI before copying their data. Create a
PostgreSQL logical dump while its database container is still running. Store
backups outside version control with restricted file permissions. Backups may
contain client evidence, chat history, and credentials.

For Docker Compose, run these commands before upgrading the images or changing
the database volume:

```sh
mkdir -p backups
chmod 700 backups
docker compose stop hoppscotch cloudbeaver open-webui
docker compose exec -T hoppscotch-db pg_dump -U hoppscotch -d hoppscotch -Fc > backups/hoppscotch-pre-upgrade.dump
docker compose cp open-webui:/app/backend/data backups/open-webui-data
docker compose cp cloudbeaver:/opt/cloudbeaver/workspace backups/cloudbeaver-workspace
chmod -R go-rwx backups
```

Use a new backup directory for subsequent upgrades so previous snapshots remain
available. Substitute the corresponding Podman commands when using that engine.

## PostgreSQL 16 to 19

The old stack stored PostgreSQL 16 in `hoppscotch-db-data` at
`/var/lib/postgresql/data`. The updated stack uses a separate
`hoppscotch-db-data-v19` volume at `/var/lib/postgresql`. The old volume is retained.

After taking the dump using the old container, pull/build the new images, start
only the new database, and restore before starting application migrations:

```sh
./blacksite build
docker compose up -d --wait hoppscotch-db
docker compose exec -T hoppscotch-db pg_restore -U hoppscotch -d hoppscotch --no-owner --exit-on-error < backups/hoppscotch-pre-upgrade.dump
docker compose up -d
./blacksite doctor
```

Restore into an empty database only. Do not repeat the restore after application
migrations. A rollback requires restoring the old application images and volume
configuration together. Keep the old volume and backups until the upgraded stack
has been verified.

## Proxy defaults

Hoppscotch receives its default proxy URL from `PROXYSCOTCH_PUBLIC_URL`, which
defaults to `http://localhost:9159`. Existing browser settings can override this
default. Use Reset Default in the Proxy interceptor settings to adopt it, and
select the Proxy interceptor when needed.
