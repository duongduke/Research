CREATE DATABASE IF NOT EXISTS wp_assist_vuln;
CREATE DATABASE IF NOT EXISTS wp_assist_fixed;
CREATE USER IF NOT EXISTS 'labuser'@'%' IDENTIFIED BY '<set-your-own-db-password>';  -- redacted: set your own password
GRANT ALL PRIVILEGES ON *.* TO 'labuser'@'%';
FLUSH PRIVILEGES;
