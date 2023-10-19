CREATE DATABASE IF NOT EXISTS ssop_dev2;

CREATE ROLE IF NOT EXISTS 'app2_developer';
CREATE ROLE IF NOT EXISTS 'app2_readonly';
CREATE ROLE IF NOT EXISTS 'app2_readwrite';

GRANT ALL ON ssop_dev2.* TO 'app2_developer';
GRANT SELECT ON ssop_dev2.* TO 'app2_readonly';
GRANT INSERT, UPDATE, DELETE ON ssop_dev2.* TO 'app2_readwrite';

#CREATE USER IF NOT EXISTS 'kirkholub'@'localhost' IDENTIFIED BY 'KpwXW8ehnlRIrMLYBBfFeR2';
#CREATE USER IF NOT EXISTS 'ucanread'@'localhost' IDENTIFIED BY 'ppu_X6LHcu7m0L';
#CREATE USER IF NOT EXISTS 'ucanreadwrite'@'localhost' IDENTIFIED BY 'wvqUgFmGU3uyWYhwWI';

GRANT 'app2_developer' TO 'kirkholub'@'localhost';
GRANT 'app2_readonly' TO 'ucanread'@'localhost';
GRANT 'app2_readonly', 'app2_readwrite' TO 'ucanreadwrite'@'localhost';

SET DEFAULT ROLE ALL TO 'kirkholub'@'localhost';
SET DEFAULT ROLE ALL TO 'ucanread'@'localhost';
SET DEFAULT ROLE ALL TO 'ucanreadwrite'@'localhost';

FLUSH PRIVILEGES;
