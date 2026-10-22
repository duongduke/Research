CREATE DATABASE IF NOT EXISTS wp_b2_v;
CREATE DATABASE IF NOT EXISTS wp_b2_f;
CREATE USER IF NOT EXISTS 'labuser'@'%' IDENTIFIED BY '<set-your-own-db-password>';  -- redacted: set your own password
GRANT ALL PRIVILEGES ON *.* TO 'labuser'@'%';
FLUSH PRIVILEGES;
