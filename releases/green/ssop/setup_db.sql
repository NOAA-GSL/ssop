CREATE DATABASE IF NOT EXISTS ssop_prod;

CREATE ROLE IF NOT EXISTS 'db_admin';
CREATE ROLE IF NOT EXISTS 'app_developer';
CREATE ROLE IF NOT EXISTS 'app_read';
CREATE ROLE IF NOT EXISTS 'app_write';

GRANT ALL ON *.* TO 'db_admin';
GRANT ALL ON ssop_prod.* TO 'app_developer';
GRANT SELECT ON ssop_prod.* TO 'app_read';
GRANT INSERT, UPDATE, DELETE ON ssop_prod.* TO 'app_write';

CREATE USER IF NOT EXISTS 'theia'@'localhost' IDENTIFIED BY 'aysisYQMKVrA8cOfqoJ';
CREATE USER IF NOT EXISTS 'developer'@'localhost' IDENTIFIED BY 'oJZz2DdY6c58GC';
CREATE USER IF NOT EXISTS 'readonly'@'localhost' IDENTIFIED BY 'ZBT62JRvey';
CREATE USER IF NOT EXISTS 'readwrite'@'localhost' IDENTIFIED BY 't2tdwm8RH1';

GRANT 'db_admin' TO 'theia'@'localhost';
GRANT 'app_developer' TO 'developer'@'localhost';
GRANT 'app_read' TO 'readonly'@'localhost';
GRANT 'app_read', 'app_write' TO 'readwrite'@'localhost';

SET DEFAULT ROLE ALL TO 'theia'@'localhost';
SET DEFAULT ROLE ALL TO 'developer'@'localhost';
SET DEFAULT ROLE ALL TO 'readonly'@'localhost';
SET DEFAULT ROLE ALL TO 'readwrite'@'localhost';

FLUSH PRIVILEGES;
