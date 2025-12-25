/* ==================================================================================
   PROJECT:  Database Security  (Healthcare System)
   FILE:     MIS.sql
   AUTHORS:  Nishin Mohammed Shahir
   PURPOSE:  Complete implementation of RBAC, Encryption, Auditing, and Recovery.
   ================================================================================== */

USE [master];
GO

-- ==================================================================================
-- PHASE 1: INFRASTRUCTURE SETUP (CLEAN INSTALL)
-- ==================================================================================
PRINT '>>> Starting Phase 1: Infrastructure...';

-- 1. CLEANUP: Drop Database if it exists (Ensures a fresh run every time)
IF EXISTS (SELECT 1 FROM sys.databases WHERE name = 'MedicalInfoSystem')
BEGIN
    ALTER DATABASE [MedicalInfoSystem] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE [MedicalInfoSystem];
END
GO

-- 2. Create Database
CREATE DATABASE [MedicalInfoSystem];
GO

USE [MedicalInfoSystem];
GO

-- 3. Create Schemas
EXEC('CREATE SCHEMA app AUTHORIZATION dbo;');   -- Data Vault
EXEC('CREATE SCHEMA api AUTHORIZATION dbo;');   -- Gateway
EXEC('CREATE SCHEMA audit AUTHORIZATION dbo;'); -- Logs
GO

-- 4. Create Core Tables
-- Staff Table (Starts Vulnerable)
CREATE TABLE app.Staff (
    StaffID       CHAR(6)       NOT NULL PRIMARY KEY,
    StaffName     NVARCHAR(100) NOT NULL,
    Position      VARCHAR(20)   NOT NULL CHECK (Position IN ('Doctor','Nurse')),
    
    -- VULNERABLE COLUMNS (Will be encrypted in Phase 3)
    PersonalPhone NVARCHAR(20)  NULL,
    HomeAddress   NVARCHAR(255) NULL,
    OfficePhone   VARCHAR(20)   NULL,

    UpdatedBy     SYSNAME       NULL DEFAULT SUSER_SNAME(),
    UpdatedAt     DATETIME2(0)  NOT NULL DEFAULT SYSUTCDATETIME()
);

-- Patient Table
CREATE TABLE app.Patient (
    PatientID     CHAR(6)       NOT NULL PRIMARY KEY,
    PatientName   NVARCHAR(100) NOT NULL,
    UpdatedBy     SYSNAME       NULL DEFAULT SUSER_SNAME(),
    UpdatedAt     DATETIME2(0)  NOT NULL DEFAULT SYSUTCDATETIME()
);

-- Appointment & Diagnosis Table
CREATE TABLE app.AppointmentAndDiagnosis (
    DiagID        INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    AppDateTime   DATETIME2(0)      NOT NULL,
    PatientID     CHAR(6)           NOT NULL,
    DoctorID      CHAR(6)           NOT NULL,
    UpdatedBy     SYSNAME           NULL DEFAULT SUSER_SNAME(),
    UpdatedAt     DATETIME2(0)      NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_AAD_Patient FOREIGN KEY (PatientID) REFERENCES app.Patient(PatientID),
    CONSTRAINT FK_AAD_Staff   FOREIGN KEY (DoctorID)  REFERENCES app.Staff(StaffID)
);
GO

-- 5. Seed Dummy Data
INSERT INTO app.Staff(StaffID, StaffName, Position, OfficePhone)
VALUES ('D1001','Dr. Ali','Doctor','03-1000-1000'),
       ('N2001','Nurse Amy','Nurse','03-2000-2000');

INSERT INTO app.Patient(PatientID, PatientName)
VALUES ('P3001','Patient Abu'),
       ('P3002','Patient Bakar');
GO


-- ==================================================================================
-- PHASE 2: SECURITY CONFIGURATION (RBAC)
-- ==================================================================================
PRINT '>>> Starting Phase 2: Security...';

-- 1. Create Server Logins (Check existence to prevent errors on re-run)
USE [master];
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'D1001') CREATE LOGIN [D1001] WITH PASSWORD = 'Doctor#2025!', CHECK_POLICY = OFF;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'N2001') CREATE LOGIN [N2001] WITH PASSWORD = 'Nurse#2025!', CHECK_POLICY = OFF;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'P3001') CREATE LOGIN [P3001] WITH PASSWORD = 'Patient1#2025!', CHECK_POLICY = OFF;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'P3002') CREATE LOGIN [P3002] WITH PASSWORD = 'Patient2#2025!', CHECK_POLICY = OFF;
GO

USE [MedicalInfoSystem];
GO

-- 2. Create Database Users
CREATE USER [user_dr_ali] FOR LOGIN [D1001];
CREATE USER [user_nurse_amy] FOR LOGIN [N2001];
CREATE USER [user_pt_3001] FOR LOGIN [P3001];
CREATE USER [user_pt_3002] FOR LOGIN [P3002];

-- 3. Create Roles & Assign Members
CREATE ROLE [r_doctor];
CREATE ROLE [r_nurse];
CREATE ROLE [r_patient];

ALTER ROLE [r_doctor]  ADD MEMBER [user_dr_ali];
ALTER ROLE [r_nurse]   ADD MEMBER [user_nurse_amy];
ALTER ROLE [r_patient] ADD MEMBER [user_pt_3001];
ALTER ROLE [r_patient] ADD MEMBER [user_pt_3002];

-- 4. Apply Permissions (Least Privilege)
-- Block direct access
DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::[app] TO [r_doctor];
DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::[app] TO [r_nurse];
DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::[app] TO [r_patient];

-- Grant API access
GRANT SELECT, EXECUTE ON SCHEMA::[api] TO [r_doctor];
GRANT SELECT, EXECUTE ON SCHEMA::[api] TO [r_nurse];
GRANT SELECT, EXECUTE ON SCHEMA::[api] TO [r_patient];
GO


-- ==================================================================================
-- PHASE 3: ENCRYPTION INFRASTRUCTURE
-- ==================================================================================
PRINT '>>> Starting Phase 3: Encryption...';

-- 1. Create Keys
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Strong#DMK#2025!';
CREATE CERTIFICATE CertForCLE WITH SUBJECT = 'Medical Info System Cert';
CREATE SYMMETRIC KEY SimKey1 WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE CertForCLE;
GO

-- 2. Add Encrypted Columns (The Fix)
PRINT '   > Preparing tables for encryption...';

-- Encrypt Patient PII
ALTER TABLE app.Patient ADD Phone_Enc VARBINARY(MAX) NULL;
ALTER TABLE app.Patient ADD HomeAddress_Enc VARBINARY(MAX) NULL;

-- Encrypt Staff PII
ALTER TABLE app.Staff ADD PersonalPhone_Enc VARBINARY(MAX) NULL;
ALTER TABLE app.Staff ADD HomeAddress_Enc VARBINARY(MAX) NULL;

-- Encrypt Medical Diagnosis
ALTER TABLE app.AppointmentAndDiagnosis ADD DiagDetails_Enc VARBINARY(MAX) NULL;
GO


-- ==================================================================================
-- PHASE 4: APPLICATION LOGIC (NURSE API)
-- ==================================================================================
PRINT '>>> Starting Phase 4: Nurse API...';

-- 1. Nurse View
CREATE VIEW api.vw_Appointments_ForNurse AS
SELECT A.DiagID, A.AppDateTime, A.PatientID, P.PatientName, A.DoctorID, S.StaffName AS DoctorName, A.UpdatedBy, A.UpdatedAt
FROM app.AppointmentAndDiagnosis A
JOIN app.Patient P ON P.PatientID = A.PatientID
JOIN app.Staff   S ON S.StaffID   = A.DoctorID;
GO

-- 2. Add Appointment
CREATE PROCEDURE api.usp_App_Add
    @PatientID CHAR(6), @DoctorID CHAR(6), @AppDateTime DATETIME2(0)
WITH EXECUTE AS OWNER AS
BEGIN
    SET NOCOUNT ON;
    IF NOT EXISTS (SELECT 1 FROM app.Patient WHERE PatientID=@PatientID) THROW 52010, 'Patient does not exist.', 1;
    INSERT INTO app.AppointmentAndDiagnosis (PatientID, DoctorID, AppDateTime, UpdatedBy, UpdatedAt)
    VALUES (@PatientID, @DoctorID, @AppDateTime, SUSER_SNAME(), SYSUTCDATETIME());
    SELECT * FROM api.vw_Appointments_ForNurse WHERE DiagID = SCOPE_IDENTITY();
END
GO

-- 3. Cancel Appointment
CREATE PROCEDURE api.usp_App_Cancel @DiagID INT WITH EXECUTE AS OWNER AS
BEGIN
    SET NOCOUNT ON;
    -- Security Check: Cannot cancel if diagnosis exists
    IF EXISTS (SELECT 1 FROM app.AppointmentAndDiagnosis WHERE DiagID=@DiagID AND DiagDetails_Enc IS NOT NULL)
        THROW 52031, 'Security Error: Cannot cancel. Doctor has already entered a diagnosis.', 1;
    
    DELETE FROM app.AppointmentAndDiagnosis WHERE DiagID=@DiagID;
    PRINT 'Appointment Cancelled Successfully.';
END
GO

GRANT SELECT  ON OBJECT::api.vw_Appointments_ForNurse TO [r_nurse];
GRANT EXECUTE ON OBJECT::api.usp_App_Add             TO [r_nurse];
GRANT EXECUTE ON OBJECT::api.usp_App_Cancel          TO [r_nurse];
GO


-- ==================================================================================
-- PHASE 5: APPLICATION LOGIC (DOCTOR API)
-- ==================================================================================
PRINT '>>> Starting Phase 5: Doctor API...';

-- 1. Add Diagnosis
CREATE PROCEDURE api.usp_Diag_Add_ByDoctor
    @DiagID INT, @DoctorID CHAR(6), @DiagDetails NVARCHAR(MAX)
WITH EXECUTE AS OWNER AS
BEGIN
    SET NOCOUNT ON;
    OPEN SYMMETRIC KEY SimKey1 DECRYPTION BY CERTIFICATE CertForCLE;
    
    UPDATE app.AppointmentAndDiagnosis
    SET DiagDetails_Enc = ENCRYPTBYKEY(KEY_GUID('SimKey1'), @DiagDetails),
        UpdatedBy       = SUSER_SNAME(),
        UpdatedAt       = SYSUTCDATETIME()
    WHERE DiagID = @DiagID AND DoctorID = @DoctorID;
    
    CLOSE SYMMETRIC KEY SimKey1;
END
GO

-- 2. View All Diagnoses
CREATE PROCEDURE api.usp_Diag_Select_All_ForDoctors WITH EXECUTE AS OWNER AS
BEGIN
    SET NOCOUNT ON;
    OPEN SYMMETRIC KEY SimKey1 DECRYPTION BY CERTIFICATE CertForCLE;
    
    SELECT A.DiagID, A.AppDateTime, P.PatientName, S.StaffName,
           CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(A.DiagDetails_Enc)) AS DiagDetails_Plain
    FROM app.AppointmentAndDiagnosis A
    JOIN app.Patient P ON P.PatientID = A.PatientID
    JOIN app.Staff   S ON S.StaffID   = A.DoctorID;
    
    CLOSE SYMMETRIC KEY SimKey1;
END
GO

-- 3. Patient View Self
CREATE PROCEDURE api.usp_Diag_Select_PatientSelf @PatientID CHAR(6) WITH EXECUTE AS OWNER AS
BEGIN
    SET NOCOUNT ON;
    OPEN SYMMETRIC KEY SimKey1 DECRYPTION BY CERTIFICATE CertForCLE;
    
    SELECT A.DiagID, A.AppDateTime, S.StaffName,
           CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(A.DiagDetails_Enc)) AS DiagDetails_Plain
    FROM app.AppointmentAndDiagnosis A
    JOIN app.Staff S ON S.StaffID = A.DoctorID
    WHERE A.PatientID = @PatientID;
    
    CLOSE SYMMETRIC KEY SimKey1;
END
GO

GRANT EXECUTE ON OBJECT::api.usp_Diag_Add_ByDoctor          TO [r_doctor];
GRANT EXECUTE ON OBJECT::api.usp_Diag_Select_All_ForDoctors TO [r_doctor];
GRANT EXECUTE ON OBJECT::api.usp_Diag_Select_PatientSelf    TO [r_patient];
GO


-- ==================================================================================
-- PHASE 6: AUDITING & TEMPORAL TABLES
-- ==================================================================================
PRINT '>>> Starting Phase 6: Auditing...';

-- 1. Create Audit Logs
CREATE TABLE audit.AuditLog_DDL(LogID INT IDENTITY(1,1), LogDateTime DATETIME2 DEFAULT SYSUTCDATETIME(), UserName SYSNAME, SqlCmd NVARCHAR(MAX));
CREATE TABLE audit.AuditLog_Logon(LogID INT IDENTITY(1,1), LogDateTime DATETIME2 DEFAULT SYSUTCDATETIME(), UserName SYSNAME, HostName NVARCHAR(100), AppName NVARCHAR(100));
GO

-- 2. Enable Temporal Tables
ALTER TABLE app.Staff ADD SysStartTime DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL DEFAULT SYSUTCDATETIME(),
                          SysEndTime   DATETIME2 GENERATED ALWAYS AS ROW END HIDDEN   NOT NULL DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.9999999'),
                          PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime);
ALTER TABLE app.Staff SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = audit.StaffHistory));

ALTER TABLE app.AppointmentAndDiagnosis ADD SysStartTime DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL DEFAULT SYSUTCDATETIME(),
                                            SysEndTime   DATETIME2 GENERATED ALWAYS AS ROW END HIDDEN   NOT NULL DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.9999999'),
                                            PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime);
ALTER TABLE app.AppointmentAndDiagnosis SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = audit.AppointmentAndDiagnosisHistory));
GO

-- 3. Create Audit Triggers
CREATE TRIGGER trg_Block_Diagnosed_Delete ON app.AppointmentAndDiagnosis
FOR DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF EXISTS (SELECT 1 FROM deleted WHERE DiagDetails_Enc IS NOT NULL)
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 54000, 'CRITICAL SECURITY ALERT: Attempt to delete a medical record containing a diagnosis. Action blocked by Table Trigger.', 1;
    END
END;
GO

CREATE TRIGGER trg_DDLAudit ON DATABASE FOR CREATE_TABLE, ALTER_TABLE, DROP_TABLE, CREATE_PROCEDURE, ALTER_PROCEDURE
AS
BEGIN
    INSERT INTO audit.AuditLog_DDL(UserName, SqlCmd) 
    VALUES (ORIGINAL_LOGIN(), EVENTDATA().value('(/EVENT_INSTANCE/TSQLCommand/CommandText)[1]','NVARCHAR(MAX)'));
END;
GO


-- ==================================================================================
-- PHASE 7: BACKUP & RECOVERY STRATEGY
-- ==================================================================================
PRINT '>>> Starting Phase 7: Backup Strategy...';
GO

CREATE PROCEDURE audit.usp_RunFullBackup
AS
BEGIN
    -- NOTE: Ensure 'C:\SQLBackups' exists on the server C: drive!
    DECLARE @DB sysname = N'MedicalInfoSystem';
    DECLARE @BackupFolder nvarchar(260) = N'C:\SQLBackups\'; 
    DECLARE @DateSuffix varchar(19) = REPLACE(CONVERT(varchar(19), GETDATE(), 120), ':','-'); 

    DECLARE @FullBackupPath nvarchar(400) = @BackupFolder + N'MedicalInfoSystem_FULL_' + @DateSuffix + N'.bak';
    DECLARE @LogBackupPath  nvarchar(400) = @BackupFolder + N'MedicalInfoSystem_LOG_'  + @DateSuffix + N'.trn';
    DECLARE @CertFile       nvarchar(400) = @BackupFolder + N'CertForCLE_' + @DateSuffix + N'.cer';
    DECLARE @KeyFile        nvarchar(400) = @BackupFolder + N'CertForCLE_' + @DateSuffix + N'.pvk';
    DECLARE @MasterKeyFile  nvarchar(400) = @BackupFolder + N'MasterKey_'  + @DateSuffix + N'.bak';

    DBCC CHECKDB(@DB) WITH NO_INFOMSGS;

    BACKUP DATABASE @DB TO DISK = @FullBackupPath WITH FORMAT, COMPRESSION, STATS = 10, NAME = 'Full Backup';

    DECLARE @SqlCmd NVARCHAR(MAX);
    SET @SqlCmd = N'USE MedicalInfoSystem; BACKUP CERTIFICATE CertForCLE TO FILE = ''' + @CertFile + ''' WITH PRIVATE KEY (FILE = ''' + @KeyFile + ''', ENCRYPTION BY PASSWORD = ''Strong#BackupPass#2025!'');';
    EXEC sp_executesql @SqlCmd;

    SET @SqlCmd = N'USE MedicalInfoSystem; BACKUP MASTER KEY TO FILE = ''' + @MasterKeyFile + ''' ENCRYPTION BY PASSWORD = ''Strong#BackupPass#2025!'';';
    EXEC sp_executesql @SqlCmd;

    BACKUP LOG @DB TO DISK = @LogBackupPath WITH COMPRESSION, STATS = 10;
    
    PRINT 'Backup Process Completed Successfully.';
END
GO

PRINT '>>> DEPLOYMENT COMPLETE: afeef_muhammad_final.sql executed successfully.';
