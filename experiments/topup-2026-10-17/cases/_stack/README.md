# Top-up cohort stack (D-035) — build & run notes

Two cases share one compose project on the lab VM `<lab-user>@<lab-ip>`
(`~/topup-lab`). Everything binds to `127.0.0.1` only; no CGI.

## Ports

| Service | Container | VM loopback |
|---|---|---|
| Joomla 4.2.7 | `topup-jl427` | 8920 |
| Joomla 4.2.8 | `topup-jl428` | 8921 |
| WordPress 6.7.1 | `topup-wp` | 8930 |
| MariaDB 10.11 | `topup-db` | 13313 |

HTTP captures in this workspace were taken through SSH local forwards of the same
loopback ports (`ssh -N -L 8920:127.0.0.1:8920 -L 8921:… -L 8930:… <lab-user>@<vm>`).

## Build / deploy (reproducible)

```bash
# 0. on the VM
mkdir -p ~/topup-lab/{compose,joomla/427,joomla/428,wordpress}
# copy this stack's compose/ + db-init/ to ~/topup-lab/compose/, and the four zips
# (Joomla 4.2.7/4.2.8, bb-1.3.7, bb-1.3.8) to ~/topup-lab/

# 1. Joomla web image (PHP 8.0.30 + mysqli); Dockerfile: _stack/joomla/php80/Dockerfile
mkdir -p ~/topup-lab/joomla/php80 && cp .../Dockerfile ~/topup-lab/joomla/php80/
cd ~/topup-lab/joomla/php80 && docker build -t rq-c1/php80-apache-joomla:1.0 .
#    → sha256:91c0b3c0c293ab2825d08481240086bc0cba86911d84679e141597edcb788f86

# 2. extract both Joomla packages into joomla/427, joomla/428 (root of the archive)
#    chmod -R 777 joomla/427 joomla/428   # installer writes configuration.php as www-data

# 3. up
cd ~/topup-lab/compose && docker compose up -d

# 4. install Joomla through the stock web installer (run from the workspace _stack/ dir,
#    against the workstation-side SSH tunnel):
cd experiments/topup-2026-10-17/cases/_stack
python3 scripts/install-joomla.py --base http://127.0.0.1:8920 \
  --db-user jl427 --db-pass 'RQ-C1-CANARY-23752-DBPASS-427' --db-name joomla427 \
  --site-name 'RQ-C1 Joomla 4.2.7' --log ../CVE-2023-23752/artifacts/install-427.log
#    then: set $secret to the canary in configuration.php and `rm -rf joomla/427/installation`
#    (same for 428 with 8921 / jl428 / RQ-C1-CANARY-23752-DBPASS-428)

# 5. WordPress (state a; 1.3.7 active). ~/topup-lab/wpcli.sh is this wrapper:
#      docker run --rm --network topup-net -e WORDPRESS_DB_HOST=db:3306 \
#        -e WORDPRESS_DB_NAME=wp_6553 -e WORDPRESS_DB_USER=wpuser \
#        -e WORDPRESS_DB_PASSWORD=<lab-db-pass> -v ~/topup-lab/wordpress:/var/www/html \
#        wordpress:cli-php8.2 wp --allow-root "$@"
docker run --rm --network topup-net -e WORDPRESS_DB_HOST=db:3306 -e WORDPRESS_DB_NAME=wp_6553 \
  -e WORDPRESS_DB_USER=wpuser -e WORDPRESS_DB_PASSWORD=<lab-db-pass> \
  -v ~/topup-lab/wordpress:/var/www/html wordpress:cli-php8.2 \
  wp --allow-root core install --url=http://127.0.0.1:8930 --title='RQ-C1 WP 6553' \
  --admin_user=labadmin --admin_password='<lab-admin-pass>' --admin_email=admin@example.test --skip-email
#    the VM has no unzip: python3 -c "import zipfile; zipfile.ZipFile('bb-1.3.7.zip').extractall('wordpress/wp-content/plugins')"
#    then: ~/topup-lab/wpcli.sh plugin activate backup-backup
```

Installer note: the Joomla installer refuses a non-`localhost` DB host unless
`JOOMLA_INSTALLATION_DISABLE_LOCALHOST_CHECK=1` is set (documented Joomla switch; the
DB is a separate container). It is set in the compose file for both Joomla services and
has no runtime effect on the API path.

## Reset

`docker compose down -v` recreates the databases from `db-init/01-init.sql`; the three
docroots are bind mounts and must be re-extracted / re-installed as above.

## Safety verification

`artifacts/safety-listeners.txt` — `ss -tlnp` and `docker ps` show no non-loopback
published container port (host `sshd` on :22 is the VM's own service, not a container).
