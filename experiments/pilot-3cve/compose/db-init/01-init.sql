-- Shared MariaDB init for the 3-CVE pilot lab.
-- One database per deployment case so cases do not share tables.
CREATE DATABASE IF NOT EXISTS wp_vuln      CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS wp_fixed     CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS drupal_vuln  CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE DATABASE IF NOT EXISTS drupal_fixed CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE DATABASE IF NOT EXISTS roundcube_vuln  CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE DATABASE IF NOT EXISTS roundcube_fixed CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

-- Single lab user used by all PHP apps (lab-only credential).
CREATE USER IF NOT EXISTS 'labuser'@'%' IDENTIFIED BY '<set-your-own-db-password>';  -- redacted: set your own password
GRANT ALL PRIVILEGES ON wp_vuln.*        TO 'labuser'@'%';
GRANT ALL PRIVILEGES ON wp_fixed.*       TO 'labuser'@'%';
GRANT ALL PRIVILEGES ON drupal_vuln.*    TO 'labuser'@'%';
GRANT ALL PRIVILEGES ON drupal_fixed.*   TO 'labuser'@'%';
GRANT ALL PRIVILEGES ON roundcube_vuln.* TO 'labuser'@'%';
GRANT ALL PRIVILEGES ON roundcube_fixed.* TO 'labuser'@'%';
FLUSH PRIVILEGES;
