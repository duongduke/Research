-- Top-up cohort DB init (lab only).
-- The two Joomla instances use DISTINCT canary DB passwords: if an API response
-- contains one of these strings, the leaked value is unambiguous (D-035 §4).
CREATE DATABASE IF NOT EXISTS joomla427 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS joomla428 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS wp_6553     CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'jl427'@'%' IDENTIFIED BY 'RQ-C1-CANARY-23752-DBPASS-427';
GRANT ALL PRIVILEGES ON joomla427.* TO 'jl427'@'%';

CREATE USER IF NOT EXISTS 'jl428'@'%' IDENTIFIED BY 'RQ-C1-CANARY-23752-DBPASS-428';
GRANT ALL PRIVILEGES ON joomla428.* TO 'jl428'@'%';

CREATE USER IF NOT EXISTS 'wpuser'@'%' IDENTIFIED BY '<set-your-own-db-password>';  -- redacted: set your own password
GRANT ALL PRIVILEGES ON wp_6553.* TO 'wpuser'@'%';

FLUSH PRIVILEGES;
