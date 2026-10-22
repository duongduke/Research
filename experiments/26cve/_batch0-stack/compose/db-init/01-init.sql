-- Batch 0 shared MariaDB init (lab-internal credentials only)
CREATE DATABASE IF NOT EXISTS wp_8942_vuln;
CREATE DATABASE IF NOT EXISTS wp_8942_fixed;
CREATE DATABASE IF NOT EXISTS wp_29447_vuln;
CREATE DATABASE IF NOT EXISTS wp_29447_fixed;
CREATE DATABASE IF NOT EXISTS wp_21661_vuln;
CREATE DATABASE IF NOT EXISTS wp_21661_fixed;
CREATE USER IF NOT EXISTS 'labuser'@'%' IDENTIFIED BY '<set-your-own-db-password>';  -- redacted: set your own password
GRANT ALL PRIVILEGES ON *.* TO 'labuser'@'%';
FLUSH PRIVILEGES;
