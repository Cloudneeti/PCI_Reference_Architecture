-- ENABLE COLUMN ENCRYPTION
USE [ContosoPayments]

-- Use the EKM to open the asymmetric KEK that was previously created in the 
-- Key Vault

CREATE ASYMMETRIC KEY CONTOSO_KEY -- Give the asymmetric KEK a name in SQL Server 
	FROM PROVIDER [AzureKeyVault_EKM_Prov]
	WITH PROVIDER_KEY_NAME = 'ContosoMasterKey', -- The name of the asymmetric KEK in Azure Key Vault
	CREATION_DISPOSITION = OPEN_EXISTING -- To indicate that this is an existing key in Azure Key Vault

-- Create the data encryption key.
-- The data encryption key can be created using any SQL Server 
-- supported algorithm or key length.
-- The DEK will be protected by the asymmetric key in the key vault

CREATE SYMMETRIC KEY DATA_ENCRYPTION_KEY
    WITH ALGORITHM=AES_256
    ENCRYPTION BY ASYMMETRIC KEY CONTOSO_KEY;

--Open the symmetric key for use in this session
OPEN SYMMETRIC KEY DATA_ENCRYPTION_KEY
DECRYPTION BY ASYMMETRIC KEY CONTOSO_KEY;


ALTER TABLE Customers  
ADD CreditCard_Number_2 varbinary(MAX )NULL, CreditCard_Expiration_2 varbinary(MAX )NULL, CreditCard_Code_2 varbinary(MAX )NULL;  
GO  

UPDATE Customers  
SET [CreditCard_Number_2] = EncryptByKey(Key_GUID('DATA_ENCRYPTION_KEY'), CreditCard_Number);  
GO  

UPDATE Customers  
SET [CreditCard_Expiration_2] = EncryptByKey(Key_GUID('DATA_ENCRYPTION_KEY'), convert(varbinary,CreditCard_Expiration));  
GO 

UPDATE Customers  
SET [CreditCard_Code_2] = EncryptByKey(Key_GUID('DATA_ENCRYPTION_KEY'), CreditCard_Code);  
GO 

--Close the symmetric key
CLOSE SYMMETRIC KEY DATA_ENCRYPTION_KEY;

-- Drop the old unencrypted columns and rename the new encrypted columns to the original name
ALTER TABLE [Customers] DROP COLUMN CreditCard_Number
GO
EXECUTE sp_rename N'[Customers].CreditCard_Number_2', N'CreditCard_Number', 'COLUMN'
GO

ALTER TABLE [Customers] DROP COLUMN CreditCard_Expiration
GO
EXECUTE sp_rename N'[Customers].CreditCard_Expiration_2', N'CreditCard_Expiration', 'COLUMN'
GO

ALTER TABLE [Customers] DROP COLUMN CreditCard_Code
GO
EXECUTE sp_rename N'[Customers].CreditCard_Code_2', N'CreditCard_Code', 'COLUMN'
GO