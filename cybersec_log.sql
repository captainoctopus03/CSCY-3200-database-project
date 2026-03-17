 -- Create the database
CREATE DATABASE IF NOT EXISTS Cybersecurity_Log;
USE Cybersecurity_Log;

-- Tables
CREATE TABLE Asset_Identity(
    AssetID VARCHAR(50) PRIMARY KEY,
    LifecycleState VARCHAR(50) NOT NULL,
    AssetLabel VARCHAR(50),
    AssetType VARCHAR(50) DEFAULT 'Workstation',
    Justification VARCHAR(100),

    CONSTRAINT chk_lifecycle CHECK (LifecycleState IN ('Active', 'Retired', 'Maintenance'))
);

CREATE TABLE Incident(
    IncidentID VARCHAR(50) PRIMARY KEY,
    CreatedTimestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ReportedBySource VARCHAR(100) NOT NULL,
    Status VARCHAR(50) NOT NULL,
    Severity VARCHAR(50),
    ParentIncidentID VARCHAR(50),

    CONSTRAINT chk_severity CHECK (Severity IN ('Low', 'Medium', 'High', 'Critical')),
    CONSTRAINT fk_parent_incident FOREIGN KEY (ParentIncidentID) REFERENCES Incident(IncidentID)
);

CREATE TABLE Incident_Asset(
    IncidentID VARCHAR(50) NOT NULL,
    AssetID VARCHAR(50) NOT NULL,
    PRIMARY KEY (IncidentID, AssetID),

    CONSTRAINT fk_ia_incident FOREIGN KEY (IncidentID) REFERENCES Incident(IncidentID),
    CONSTRAINT fk_ia_asset FOREIGN KEY (AssetID) REFERENCES Asset_Identity(AssetID)
);

CREATE TABLE IOC(
    IOCType VARCHAR(50) NOT NULL,
    IOCValue VARCHAR(255) NOT NULL,
    FirstSeen DATETIME NOT NULL,
    LastSeen DATETIME,
    IncidentID VARCHAR(50) NOT NULL,
    PRIMARY KEY (IOCType, IOCValue),

    CONSTRAINT fk_ioc_incident FOREIGN KEY (IncidentID) REFERENCES Incident(IncidentID),
    CONSTRAINT chk_ioc_type CHECK (IOCType IN ('IP', 'Domain', 'FileHash', 'URL'))
);

CREATE TABLE Alert_Event(
    SourceSystem VARCHAR(50) NOT NULL,
    SourceEventID VARCHAR(100) NOT NULL,
    EventTimestamp DATETIME NOT NULL,
    RawSummary VARCHAR(500),
    IncidentID VARCHAR(50),
    PRIMARY KEY (SourceSystem, SourceEventID),
    UNIQUE (SourceEventID),

    CONSTRAINT fk_alert_incident FOREIGN KEY (IncidentID) REFERENCES Incident(IncidentID)
);

CREATE TABLE Response_Action(
    ActionID VARCHAR(50) PRIMARY KEY,
    Owner VARCHAR(50) NOT NULL,
    DueDate DATETIME,
    Status VARCHAR(50) DEFAULT 'Open',
    IncidentID VARCHAR(50) NOT NULL,

    CONSTRAINT fk_ra_incident FOREIGN KEY (IncidentID) References Incident(IncidentID),
    CONSTRAINT chk_ra_status CHECK (Status IN ('Open', 'In Progress', 'Completed'))
);

CREATE TABLE Evidence(
    EvidenceID VARCHAR(50) PRIMARY KEY,
    StorageLocation VARCHAR(255) NOT NULL,
    CollectedBy VARCHAR(50),
    CollectedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    IntegrityHash CHAR(64) UNIQUE,
    IncidentID VARCHAR(50) NOT NULL,

    CONSTRAINT fk_ev_incident FOREIGN KEY (IncidentID) References Incident(IncidentID)
); 

-- Insert statements (we don't have our data quite yet so the following insert statements are populating with bogus data for demonstration purposes)
-- Populating asset_identity
INSERT INTO Asset_Identity (AssetID, LifecycleState, AssetLabel, AssetType) VALUES
('SRV-WEB-01', 'Active', 'Web Server 1', 'Server'),
('SRV-DB-01', 'Active', 'Database Primary', 'Server'),
('WKST-HR-05', 'Active', 'HR Laptop', 'Workstation'),
('WKST-IT-01', 'Active', 'Admin Desktop', 'Workstation'),
('SRV-MAIL-01', 'Retired', 'Old Mail Server', 'Server'),
('FW-BORDER-01', 'Active', 'Border Firewall', 'Networking'),
('SW-CORE-01', 'Active', 'Core Switch', 'Networking'),
('WKST-DEV-12', 'Maintenance', 'Dev Laptop', 'Workstation'),
('SRV-PROX-01', 'Active', 'Hypervisor Host', 'Server'),
('WKST-EXEC-01', 'Active', 'CEO Laptop', 'Workstation');

-- Populating incident
INSERT INTO Incident (IncidentID, ReportedBySource, Status, Severity, ParentIncidentID) VALUES
('INC-2026-002', 'Phishing_Report', 'In Progress', 'Medium', NULL),
('INC-2026-003', 'IDS_Alert', 'Open', 'High', NULL),
('INC-2026-004', 'Manual_Entry', 'Closed', 'Low', NULL),
('INC-2026-005', 'CrowdStrike', 'In Progress', 'Critical', NULL),
('INC-2026-006', 'DLP_Alert', 'Open', 'Medium', NULL),
('INC-2026-007', 'Vulnerability_Scan', 'Open', 'Low', NULL),
('INC-2026-008', 'EDR_Alert', 'In Progress', 'Critical', 'INC-2026-005'), -- Sub-incident
('INC-2026-009', 'Wazuh', 'Open', 'High', 'INC-2026-003'), -- Sub-incident
('INC-2026-010', 'Help_Desk', 'Closed', 'Low', NULL),
('INC-2026-011', 'External_Intel', 'Open', 'High', NULL);

-- 3. Populating Incident_Asset (10 rows - Mapping m:n)
INSERT INTO Incident_Asset (IncidentID, AssetID) VALUES
('INC-2026-002', 'WKST-HR-05'),
('INC-2026-003', 'SRV-WEB-01'),
('INC-2026-003', 'FW-BORDER-01'),
('INC-2026-005', 'SRV-DB-01'),
('INC-2026-005', 'SRV-PROX-01'),
('INC-2026-008', 'SRV-DB-01'),
('INC-2026-009', 'SRV-WEB-01'),
('INC-2026-006', 'WKST-EXEC-01'),
('INC-2026-011', 'SW-CORE-01'),
('INC-2026-004', 'WKST-IT-01');

-- Populating IOC
INSERT INTO IOC (IOCType, IOCValue, FirstSeen, IncidentID) VALUES
('IP', '185.244.25.12', NOW(), 'INC-2026-003'),
('Domain', 'secure-login-update.com', NOW(), 'INC-2026-002'),
('FileHash', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', NOW(), 'INC-2026-005'),
('URL', 'http://malware-dist.org/payload.exe', NOW(), 'INC-2026-005'),
('IP', '45.12.33.101', NOW(), 'INC-2026-009'),
('Domain', 'data-exfil-sink.net', NOW(), 'INC-2026-006'),
('FileHash', '5d41402abc4b2a76b9719d911017c592', NOW(), 'INC-2026-008'),
('IP', '103.25.1.5', NOW(), 'INC-2026-011'),
('URL', 'https://bit.ly/fake-invoice', NOW(), 'INC-2026-002'),
('IP', '192.168.50.200', NOW(), 'INC-2026-007');

-- Populating alert_event
INSERT INTO Alert_Event (SourceSystem, SourceEventID, EventTimestamp, RawSummary, IncidentID) VALUES
('Suricata', 'EV-1001', NOW(), 'Potential SSH Brute Force', 'INC-2026-003'),
('Office365', 'EV-9921', NOW(), 'Suspicious Inbox Rule Created', 'INC-2026-002'),
('CrowdStrike', 'CS-552', NOW(), 'LSASS Memory Dump Detected', 'INC-2026-005'),
('PaloAlto', 'PA-88', NOW(), 'Outbound connection to known C2', 'INC-2026-003'),
('Wazuh', 'WZ-404', NOW(), 'Unauthorized file change in /etc/', 'INC-2026-009'),
('Windows_Event', '4624-99', NOW(), 'Successful login from unusual IP', 'INC-2026-005'),
('Snort', 'SN-12', NOW(), 'SQL Injection Pattern Detected', 'INC-2026-003'),
('DLP_Engine', 'DLP-01', NOW(), 'Sensitive PDF uploaded to Mega.nz', 'INC-2026-006'),
('Nessus', 'NS-500', NOW(), 'Critical Apache Vulnerability Found', 'INC-2026-007'),
('Gmail_Log', 'GM-77', NOW(), 'External forwarder enabled', 'INC-2026-002');

-- Populating response_action
INSERT INTO Response_Action (ActionID, Owner, DueDate, Status, IncidentID) VALUES
('ACT-01', 'Admin_Dan', '2026-03-20', 'In Progress', 'INC-2026-003'),
('ACT-02', 'Admin_Dan', '2026-03-17', 'Completed', 'INC-2026-002'),
('ACT-03', 'Sec_Analyst_B', '2026-03-16', 'Open', 'INC-2026-005'),
('ACT-04', 'Forensics_Team', '2026-03-25', 'Open', 'INC-2026-005'),
('ACT-05', 'Admin_Dan', '2026-03-18', 'Completed', 'INC-2026-004'),
('ACT-06', 'Network_Ops', '2026-03-19', 'In Progress', 'INC-2026-003'),
('ACT-07', 'HR_Manager', '2026-03-21', 'Open', 'INC-2026-006'),
('ACT-08', 'Sec_Analyst_B', '2026-03-16', 'In Progress', 'INC-2026-008'),
('ACT-09', 'IT_Support', '2026-03-30', 'Open', 'INC-2026-007'),
('ACT-10', 'Admin_Dan', '2026-03-17', 'Completed', 'INC-2026-010');

-- Populating evidence
INSERT INTO Evidence (EvidenceID, StorageLocation, CollectedBy, IntegrityHash, IncidentID) VALUES
('EV-001', '/mnt/san/forensics/mem_dump.bin', 'Admin_Dan', 'HASH_001_XYZ', 'INC-2026-005'),
('EV-002', '/mnt/san/forensics/pcap_capture.pcap', 'Network_Ops', 'HASH_002_ABC', 'INC-2026-003'),
('EV-003', 'S3://bucket/phish_email.eml', 'Sec_Analyst_B', 'HASH_003_LMN', 'INC-2026-002'),
('EV-004', '/local/logs/auth_log.txt', 'Admin_Dan', 'HASH_004_DEF', 'INC-2026-003'),
('EV-005', '/mnt/san/forensics/disk_image.ad1', 'Forensics_Team', 'HASH_005_GHI', 'INC-2026-005'),
('EV-006', '/local/screenshots/browser_history.png', 'Admin_Dan', 'HASH_006_JKL', 'INC-2026-006'),
('EV-007', '/mnt/san/forensics/db_audit.csv', 'Sec_Analyst_B', 'HASH_007_OPQ', 'INC-2026-008'),
('EV-008', '/local/config/firewall_rules.bak', 'Network_Ops', 'HASH_008_RST', 'INC-2026-011'),
('EV-009', '/mnt/san/forensics/process_list.txt', 'Admin_Dan', 'HASH_009_UVW', 'INC-2026-009'),
('EV-010', 'S3://bucket/malware_sample.exe', 'Sec_Analyst_B', 'HASH_010_123', 'INC-2026-005');

-- Select statements
SELECT * FROM Incident;
SELECT * FROM IOC;

-- Query 1
SELECT Owner FROM Response_Action WHERE IncidentID = 'INC-2026-007';
-- Query 2
SELECT IOCType FROM IOC WHERE IncidentID = 'INC-2026-003';
-- Query 3
SELECT i.Status FROM Incident i JOIN Alert_Event a ON i.IncidentID = a.IncidentID WHERE DATE(a.EventTimestamp) = CURRENT_DATE AND a.SourceSystem = 'Suricata';
-- Query 4
SELECT i.ParentIncidentID  FROM Incident i JOIN Alert_Event a ON i.IncidentID = a.IncidentID WHERE a.SourceSystem = 'EDR_Alert' AND i.ParentIncidentID IS NOT NULL;
-- Query 5
SELECT ioc.IOCType FROM IOC ioc JOIN Incident i ON ioc.IncidentID = i.IncidentID WHERE i.Status = 'In Progress'  AND i.Severity = 'Medium';
