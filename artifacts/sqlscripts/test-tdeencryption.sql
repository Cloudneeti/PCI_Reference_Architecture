USE master
IF (SELECT name 
FROM sys.asymmetric_keys
WHERE name = 'TDE_KEY') IN (N'TDE_KEY')
RETURN;
ELSE
THROW 51000, 'The record does not exist.', 1;