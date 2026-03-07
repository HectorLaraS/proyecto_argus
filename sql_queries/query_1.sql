IF DB_ID('ARGUS') IS NULL
BEGIN
    CREATE DATABASE ARGUS;
END
GO

USE ARGUS;
GO

IF OBJECT_ID('dbo.sw_traps', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.sw_traps (
        trap_id BIGINT IDENTITY(1,1) PRIMARY KEY,
        received_at DATETIME2 NOT NULL,
        src_ip VARCHAR(64) NOT NULL,
        src_port INT NULL,
        community VARCHAR(100) NOT NULL,
        enterprise_oid VARCHAR(255) NULL,
        trap_oid VARCHAR(255) NULL,
        vendor_name VARCHAR(255) NULL,
        raw_payload_json NVARCHAR(MAX) NOT NULL,
        created_at DATETIME2 NOT NULL CONSTRAINT DF_sw_traps_created_at DEFAULT SYSUTCDATETIME()
    );
END
GO

IF NOT EXISTS (
    SELECT 1
    FROM sys.indexes
    WHERE name = 'IX_sw_traps_received_at'
      AND object_id = OBJECT_ID('dbo.sw_traps')
)
BEGIN
    CREATE INDEX IX_sw_traps_received_at
        ON dbo.sw_traps(received_at DESC);
END
GO

IF NOT EXISTS (
    SELECT 1
    FROM sys.indexes
    WHERE name = 'IX_sw_traps_community'
      AND object_id = OBJECT_ID('dbo.sw_traps')
)
BEGIN
    CREATE INDEX IX_sw_traps_community
        ON dbo.sw_traps(community);
END
GO

IF NOT EXISTS (
    SELECT 1
    FROM sys.indexes
    WHERE name = 'IX_sw_traps_src_ip'
      AND object_id = OBJECT_ID('dbo.sw_traps')
)
BEGIN
    CREATE INDEX IX_sw_traps_src_ip
        ON dbo.sw_traps(src_ip);
END
GO

IF NOT EXISTS (
    SELECT 1
    FROM sys.indexes
    WHERE name = 'IX_sw_traps_trap_oid'
      AND object_id = OBJECT_ID('dbo.sw_traps')
)
BEGIN
    CREATE INDEX IX_sw_traps_trap_oid
        ON dbo.sw_traps(trap_oid);
END
GO