USE [Master]

-- Use the EKM to open the asymmetric KEK that was previously created in the
-- Key Vault

CREATE ASYMMETRIC KEY TDE_KEY -- Give the asymmetric KEK a name in SQL Server
        FROM PROVIDER AzureKeyVault_EKM_Prov WITH
        PROVIDER_KEY_NAME = 'ContosoMasterKey', -- The name of the asymmetric KEK in Azure Key Vault
        CREATION_DISPOSITION = OPEN_EXISTING -- To indicate that this is an existing key in Azure Key Vault

-- Create a SQL Server Login associated with the KEK for the Database engine
-- to use whenever it loads a database encrypted by TDE

CREATE LOGIN TDE_Login
FROM ASYMMETRIC KEY TDE_KEY ;
GO

-- Create a SQL credential for the SQL Server Database Engine to use to
-- access the Key Vault EKM during database load

CREATE CREDENTIAL Azure_EKM_TDE_cred
    WITH IDENTITY =  $(keyVaultName),
    SECRET = $(secret)
FOR CRYPTOGRAPHIC PROVIDER AzureKeyVault_EKM_Prov

-- Alter the TDE Login to add this Credential for use by the Database Engine
-- to access the Key Vault

ALTER LOGIN TDE_Login
ADD CREDENTIAL Azure_EKM_TDE_cred ;
GO

-- Create the database encryption key (DEK) that will be used for TDE.
-- The DEK can be created using any SQL Server supported Algorithm
-- or Key Length.
-- The DEK will be protected by the Asymmetric KEK in the Key Vault
USE [ContosoPayments];
GO
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM  = AES_256
ENCRYPTION BY SERVER ASYMMETRIC KEY TDE_KEY;
GO

-- Alter the database to enable transparent data encryption.
-- This uses the asymmetric KEK you imported from Azure Key Vault to wrap your DEK.
ALTER DATABASE [ContosoPayments]
SET ENCRYPTION ON ;
GO