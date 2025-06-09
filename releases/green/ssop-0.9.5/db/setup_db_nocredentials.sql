CREATE DATABASE IF NOT EXISTS ssop_dev;

CREATE ROLE IF NOT EXISTS 'app_developer';
CREATE ROLE IF NOT EXISTS 'app_read';
CREATE ROLE IF NOT EXISTS 'app_write';

GRANT ALL ON ssop_dev.* TO 'app_developer';
GRANT SELECT ON ssop_dev.* TO 'app_read';
GRANT INSERT, UPDATE, DELETE ON ssop_dev.* TO 'app_write';

CREATE USER IF NOT EXISTS 'theia'@'localhost' IDENTIFIED BY 'secret1';
CREATE USER IF NOT EXISTS 'developer'@'localhost' IDENTIFIED BY 'secret2';
CREATE USER IF NOT EXISTS 'readonly'@'localhost' IDENTIFIED BY 'read_user_secret';
CREATE USER IF NOT EXISTS 'readwrite'@'localhost' IDENTIFIED BY 'rw_user_secret';

GRANT 'app_developer' TO 'zeus'@'localhost';
GRANT 'app_developer' TO 'developer'@'localhost';
GRANT 'app_read' TO 'readonly'@'localhost';
GRANT 'app_read', 'app_write' TO 'readwrite'@'localhost';

SET DEFAULT ROLE ALL TO 'zeus'@'localhost';
SET DEFAULT ROLE ALL TO 'developer'@'localhost';
SET DEFAULT ROLE ALL TO 'readonly'@'localhost';
SET DEFAULT ROLE ALL TO 'readwrite'@'localhost';

FLUSH PRIVILEGES;
