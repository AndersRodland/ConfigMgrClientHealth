-- SQL query to create and/or upgrade the database and tables for ConfigMgr Client Health

-- IF CREATING DATABASE FOR FIRST TIME:
-- Remember to grant 'domain\domain computers' DATAREADER and DATAWRITER rights on the ClientHealth database
-- after you execute this query and database is created.


-- START QUERY
-- Create database if not exist:
GO
IF NOT EXISTS (SELECT [name] FROM sys.databases WHERE [name] = 'ClientHealth')
CREATE DATABASE ClientHealth

GO
USE ClientHealth

-- Create Configuration table if not exist:
GO
IF NOT EXISTS (SELECT [name] FROM sys.tables WHERE [name] = 'Configuration')
CREATE TABLE dbo.Configuration
(
    Name varchar(50) NOT NULL UNIQUE,
    Version varchar (10) NOT NULL
)

-- Create Clients table if not exist:
IF NOT EXISTS (SELECT [name] FROM sys.tables WHERE [name] = 'Clients')
CREATE TABLE dbo.Clients
(
    Hostname varchar(100) NOT NULL PRIMARY KEY,
    OperatingSystem varchar (100) NOT NULL,
    Architecture varchar(10) NOT NULL,
    Build varchar(50) NOT NULL,
    Manufacturer varchar(50),
    Model varchar(50),
    InstallDate smalldatetime,
    OSUpdates smalldatetime,
    LastLoggedOnUser varchar(50),
    ClientVersion varchar(20),
    PSVersion float,
    PSBuild int,
    Sitecode varchar(3),
    Domain varchar(50),
    MaxLogSize int,
    MaxLogHistory int,
    CacheSize int,
    ClientCertificate varchar(50),
    ProvisioningMode varchar(50),
    DNS varchar(100),
    Drivers varchar(100),
    Updates varchar(100),
    PendingReboot varchar(50),
    LastBootTime smalldatetime,
    OSDiskFreeSpace float,
    Services varchar(50),
    AdminShare varchar(50),
    StateMessages varchar(50),
    WUAHandler varchar(50),
    WMI varchar(50),
    RefreshComplianceState smalldatetime,
    ClientInstalled smalldatetime,
    Version varchar(10),
    Timestamp datetime,
    HWInventory smalldatetime,
    SWMetering varchar(50),
    BITS varchar(50),
    PatchLevel int,
    ClientInstalledReason varchar(200)
)
else

-- START Changes to database --
-- Add columns if needed
IF NOT EXISTS (SELECT * FROM sys.columns WHERE  object_id = OBJECT_ID(N'[dbo].[Clients]') AND name = 'HWInventory') ALTER TABLE dbo.Clients ADD HWInventory smalldatetime
IF NOT EXISTS (SELECT * FROM sys.columns WHERE  object_id = OBJECT_ID(N'[dbo].[Clients]') AND name = 'SWMetering') ALTER TABLE dbo.Clients ADD SWMetering varchar(50)
IF NOT EXISTS (SELECT * FROM sys.columns WHERE  object_id = OBJECT_ID(N'[dbo].[Clients]') AND name = 'BITS') ALTER TABLE dbo.Clients ADD BITS varchar(50)
IF NOT EXISTS (SELECT * FROM sys.columns WHERE  object_id = OBJECT_ID(N'[dbo].[Clients]') AND name = 'PatchLevel') ALTER TABLE dbo.Clients ADD PatchLevel int
IF NOT EXISTS (SELECT * FROM sys.columns WHERE  object_id = OBJECT_ID(N'[dbo].[Clients]') AND name = 'ClientInstalledReason') ALTER TABLE dbo.Clients ADD ClientInstalledReason varchar(200)
IF NOT EXISTS (SELECT * FROM sys.columns WHERE  object_id = OBJECT_ID(N'[dbo].[Clients]') AND name = 'RefreshComplianceState') ALTER TABLE dbo.Clients ADD RefreshComplianceState smalldatetime


-- Modify columns if needed
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'Hostname' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN Hostname VARCHAR(100) NOT NULL
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'Build' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN Build VARCHAR(100) NOT NULL
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'Manufacturer' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN Manufacturer VARCHAR(100) NOT NULL
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'Model' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN Model VARCHAR(100) NOT NULL
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'LastLoggedOnUser' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN LastLoggedOnUser VARCHAR(100) NOT NULL
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'ClientVersion' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN ClientVersion VARCHAR(100) NOT NULL
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'Drivers' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN Build VARCHAR(100) NOT NULL
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'Domain' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN Domain VARCHAR(100) NOT NULL
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'DNS' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN DNS VARCHAR(200) NOT NULL
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'Updates' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN Updates VARCHAR(200) NOT NULL
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'Services' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN Services VARCHAR(200) NOT NULL

-- Set latest ConfigMgr Client Health database version:
GO
begin tran
if exists (SELECT * FROM dbo.Configuration WITH (updlock,serializable) WHERE Name='ClientHealth')
begin
    IF EXISTS (SELECT * FROM dbo.Configuration WITH (updlock,serializable) WHERE Name='ClientHealth' AND Version < '0.7.5')
    UPDATE dbo.Configuration SET Version='0.7.5' WHERE Name = 'ClientHealth'
end
else
begin
    INSERT INTO dbo.Configuration (Name, Version)
    VALUES ('ClientHealth', '0.7.5')
end
commit tran

-- End of query
