# FreeRADIUS AAA Methods Documentation

## Overview

This document provides comprehensive information about all Authentication, Authorization, and Accounting (AAA) methods available in FreeRADIUS, with special emphasis on SQL-based implementations. FreeRADIUS supports multiple authentication backends, flexible authorization mechanisms, and detailed accounting methods to meet diverse enterprise requirements.

## Authentication Methods

### 1. SQL-Based Authentication

#### Core SQL Authentication
SQL authentication is one of the most widely used methods in FreeRADIUS, providing centralized user management and flexible password storage.

**Configuration:**
```
sql {
    dialect = "mysql"
    driver = "${dialect}"
    server = "localhost"
    port = 3306
    login = "radius"
    password = "radpass"
    radius_db = "radius"

    # User authentication tables
    authcheck_table = "radcheck"
    authreply_table = "radreply"
    groupcheck_table = "radgroupcheck"
    groupreply_table = "radgroupreply"
    usergroup_table = "radusergroup"
}
```

**Database Schema:**
```sql
-- User check items (credentials and constraints)
CREATE TABLE radcheck (
    id int(11) unsigned NOT NULL auto_increment,
    username varchar(64) NOT NULL default '',
    attribute varchar(64) NOT NULL default '',
    op char(2) NOT NULL DEFAULT '==',
    value varchar(253) NOT NULL default '',
    PRIMARY KEY (id),
    KEY username (username(32))
);

-- User reply items (attributes to return)
CREATE TABLE radreply (
    id int(11) unsigned NOT NULL auto_increment,
    username varchar(64) NOT NULL default '',
    attribute varchar(64) NOT NULL default '',
    op char(2) NOT NULL DEFAULT '=',
    value varchar(253) NOT NULL default '',
    PRIMARY KEY (id),
    KEY username (username(32))
);

-- Group check items
CREATE TABLE radgroupcheck (
    id int(11) unsigned NOT NULL auto_increment,
    groupname varchar(64) NOT NULL default '',
    attribute varchar(64) NOT NULL default '',
    op char(2) NOT NULL DEFAULT '==',
    value varchar(253) NOT NULL default '',
    PRIMARY KEY (id),
    KEY groupname (groupname(32))
);

-- Group reply items
CREATE TABLE radgroupreply (
    id int(11) unsigned NOT NULL auto_increment,
    groupname varchar(64) NOT NULL default '',
    attribute varchar(64) NOT NULL default '',
    op char(2) NOT NULL DEFAULT '=',
    value varchar(253) NOT NULL default '',
    PRIMARY KEY (id),
    KEY groupname (groupname(32))
);

-- User-group membership
CREATE TABLE radusergroup (
    id int(11) unsigned NOT NULL auto_increment,
    username varchar(64) NOT NULL default '',
    groupname varchar(64) NOT NULL default '',
    priority int(11) NOT NULL default '1',
    PRIMARY KEY (id),
    KEY username (username(32))
);
```

**Authentication Queries:**
```sql
-- User check query
authorize_check_query = "
    SELECT id, username, attribute, value, op
    FROM radcheck
    WHERE username = '%{SQL-User-Name}'
    ORDER BY id"

-- User reply query
authorize_reply_query = "
    SELECT id, username, attribute, value, op
    FROM radreply
    WHERE username = '%{SQL-User-Name}'
    ORDER BY id"

-- Group membership query
group_membership_query = "
    SELECT groupname
    FROM radusergroup
    WHERE username = '%{SQL-User-Name}'
    ORDER BY priority"

-- Group check query
authorize_group_check_query = "
    SELECT id, groupname, attribute, value, op
    FROM radgroupcheck
    WHERE groupname = '%{SQL-Group}'
    ORDER BY id"

-- Group reply query
authorize_group_reply_query = "
    SELECT id, groupname, attribute, value, op
    FROM radgroupreply
    WHERE groupname = '%{SQL-Group}'
    ORDER BY id"
```

**SQL Authentication Examples:**
```sql
-- User with PAP authentication
INSERT INTO radcheck (username, attribute, op, value) VALUES ('john', 'Password.Cleartext', ':=', 'mypassword');

-- User with CHAP authentication
INSERT INTO radcheck (username, attribute, op, value) VALUES ('mary', 'Password.Cleartext', ':=', 'secret123');

-- User with simultaneous use limit
INSERT INTO radcheck (username, attribute, op, value) VALUES ('john', 'Simultaneous-Use', ':=', '1');

-- User with session timeout
INSERT INTO radreply (username, attribute, op, value) VALUES ('john', 'Session-Timeout', ':=', '3600');

-- User with IP address assignment
INSERT INTO radreply (username, attribute, op, value) VALUES ('john', 'Framed-IP-Address', ':=', '192.168.1.100');

-- Group-based authentication
INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES ('staff', 'Password.Cleartext', ':=', 'staffpass');
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES ('staff', 'Session-Timeout', ':=', '7200');
INSERT INTO radusergroup (username, groupname, priority) VALUES ('jane', 'staff', 1);
```

### 2. LDAP Authentication

LDAP authentication provides integration with directory services like Active Directory, OpenLDAP, and others.

**Configuration:**
```
ldap {
    server = "ldap.example.com"
    identity = "cn=freeradius,dc=example,dc=com"
    password = "ldappass"
    base_dn = "dc=example,dc=com"

    user {
        base_dn = "ou=people,${..base_dn}"
        filter = "(uid=%{%{Stripped-User-Name}:-%{User-Name}})"
        scope = "sub"
        # Access attributes
        access_attribute = "dialupAccess"
        access_positive = yes
    }

    group {
        base_dn = "ou=groups,${..base_dn}"
        filter = "(objectClass=groupOfNames)"
        scope = "sub"
        name_attribute = "cn"
        membership_attribute = "member"
        membership_filter = "(member=%{control.Ldap-UserDn})"
    }
}
```

**LDAP Authentication Types:**
- **Bind Authentication**: FreeRADIUS binds to LDAP as the user
- **Password Compare**: Extract password from LDAP and compare locally
- **Group-based Access**: Check group membership for authorization

### 3. File-Based Authentication

Traditional file-based authentication using the `users` file.

**Configuration:**
```
files {
    filename = ${confdir}/users
    acctusersfile = ${confdir}/acct_users
    preproxy_usersfile = ${confdir}/preproxy_users
}
```

**Example Users File:**
```
# User with PAP authentication
john    Password.Cleartext := "mypassword"
        Reply-Message := "Hello, %{User-Name}"

# User with group assignment
mary    Password.Cleartext := "secret123"
        Reply-Message := "Welcome to the network"

# Default entry with fallthrough
DEFAULT Auth-Type := Reject
        Reply-Message := "Access denied"
```

### 4. PAM Authentication

System-level authentication using PAM (Pluggable Authentication Modules).

**Configuration:**
```
pam {
    pam_auth = radiusd
}
```

### 5. Unix System Authentication

Direct authentication against Unix system accounts.

**Configuration:**
```
unix {
    radwtmp = ${logdir}/radwtmp
}
```

### 6. Kerberos Authentication

Integration with Kerberos for single sign-on environments.

**Configuration:**
```
krb5 {
    keytab = /etc/raddb/keytab
    service_principal = "radius/radius.example.com@REALM"
}
```

### 7. Windows Domain Authentication

Integration with Windows Active Directory using ntlm_auth.

**Configuration:**
```
ntlm_auth {
    program = "/usr/bin/ntlm_auth --request-nt-key --domain=DOMAIN --username=%{mschap:User-Name} --password=%{User-Password}"
}
```

## Authorization Methods

### 1. SQL-Based Authorization

SQL authorization uses the same database structure as authentication but focuses on attribute assignment and access control.

**Authorization Flow:**
1. User check items are evaluated first
2. If successful, user reply items are processed
3. Group processing occurs based on configuration
4. Group check items are evaluated
5. Group reply items are processed

**Advanced SQL Authorization Features:**

#### Simultaneous Use Control
```sql
-- Enable simultaneous use checking
INSERT INTO radcheck (username, attribute, op, value) VALUES ('john', 'Simultaneous-Use', ':=', '1');

-- Check current sessions
SELECT COUNT(*) FROM radacct
WHERE username = 'john'
AND acctstoptime IS NULL;
```

#### Time-Based Access Control
```sql
-- Time-based access using Login-Time
INSERT INTO radcheck (username, attribute, op, value) VALUES ('student', 'Login-Time', ':=', 'Mo-Fr0800-1800');

-- Date-based expiration
INSERT INTO radcheck (username, attribute, op, value) VALUES ('temp_user', 'Expiration', ':=', 'Jan 31 2025');
```

#### IP Address Management
```sql
-- Static IP assignment
INSERT INTO radreply (username, attribute, op, value) VALUES ('server1', 'Framed-IP-Address', ':=', '192.168.1.10');

-- IP pool assignment
INSERT INTO radreply (username, attribute, op, value) VALUES ('dynamic_user', 'Pool-Name', ':=', 'main_pool');
```

### 2. LDAP Authorization

LDAP authorization can extract user attributes and group memberships.

**LDAP Attribute Mapping:**
```
ldap {
    user {
        # Map LDAP attributes to RADIUS attributes
        update {
            control.Password-With-Header += 'userPassword'
            control.NT-Password := 'sambaNTPassword'
            reply.Reply-Message := 'description'
            reply.Framed-IP-Address := 'radiusFramedIPAddress'
        }
    }
}
```

### 3. File-Based Authorization

The `users` file supports complex authorization rules.

**Advanced Users File Examples:**
```
# User with multiple conditions
john    Password.Cleartext := "mypassword", NAS-IP-Address == "192.168.1.1"
        Service-Type := Framed-User,
        Framed-Protocol := PPP,
        Framed-IP-Address := 192.168.1.100

# Group-based authorization
DEFAULT Group == "staff", Password.Cleartext := "staffpass"
        Service-Type := Framed-User,
        Session-Timeout := 7200,
        Fall-Through := Yes

# Huntgroup-based authorization
DEFAULT Huntgroup-Name == "dialup", Password.Cleartext := "dialpass"
        Service-Type := Framed-User,
        Framed-Protocol := PPP

# Reject all others
DEFAULT Auth-Type := Reject
        Reply-Message := "Access denied"
```

## Accounting Methods

### 1. SQL-Based Accounting

SQL accounting provides comprehensive session tracking and billing capabilities.

**Database Schema:**
```sql
CREATE TABLE radacct (
    radacctid bigint(21) NOT NULL auto_increment,
    acctsessionid varchar(64) NOT NULL default '',
    acctuniqueid varchar(32) NOT NULL default '',
    username varchar(64) NOT NULL default '',
    groupname varchar(64) NOT NULL default '',
    realm varchar(64) default '',
    nasipaddress varchar(15) NOT NULL default '',
    nasportid varchar(32) default NULL,
    nasporttype varchar(32) default NULL,
    acctstarttime datetime NULL default NULL,
    acctupdatetime datetime NULL default NULL,
    acctstoptime datetime NULL default NULL,
    acctinterval int(12) default NULL,
    acctsessiontime int(12) unsigned default NULL,
    acctauthentic varchar(32) default NULL,
    connectinfo_start varchar(50) default NULL,
    connectinfo_stop varchar(50) default NULL,
    acctinputoctets bigint(20) default NULL,
    acctoutputoctets bigint(20) default NULL,
    calledstationid varchar(50) NOT NULL default '',
    callingstationid varchar(50) NOT NULL default '',
    acctterminatecause varchar(32) NOT NULL default '',
    servicetype varchar(32) default NULL,
    framedprotocol varchar(32) default NULL,
    framedipaddress varchar(15) NOT NULL default '',
    framedipv6address varchar(45) NOT NULL default '',
    framedipv6prefix varchar(45) NOT NULL default '',
    framedinterfaceid varchar(44) NOT NULL default '',
    delegatedipv6prefix varchar(45) NOT NULL default '',
    class varchar(64) default NULL,
    PRIMARY KEY (radacctid),
    UNIQUE KEY acctuniqueid (acctuniqueid),
    KEY username (username),
    KEY framedipaddress (framedipaddress),
    KEY acctsessionid (acctsessionid),
    KEY acctsessiontime (acctsessiontime),
    KEY acctstarttime (acctstarttime),
    KEY acctstoptime (acctstoptime),
    KEY nasipaddress (nasipaddress)
);
```

**Accounting Queries:**

#### Session Start
```sql
INSERT INTO radacct (
    acctsessionid, acctuniqueid, username, realm, nasipaddress,
    nasportid, nasporttype, acctstarttime, acctupdatetime,
    calledstationid, callingstationid, servicetype, framedprotocol,
    framedipaddress, class
) VALUES (
    '%{Acct-Session-Id}', '%{Acct-Unique-Session-Id}', '%{SQL-User-Name}',
    '%{Realm}', '%{NAS-IP-Address}', '%{NAS-Port-ID}', '%{NAS-Port-Type}',
    FROM_UNIXTIME(%{integer:Event-Timestamp}), FROM_UNIXTIME(%{integer:Event-Timestamp}),
    '%{Called-Station-Id}', '%{Calling-Station-Id}', '%{Service-Type}',
    '%{Framed-Protocol}', '%{Framed-IP-Address}', '%{Class}'
);
```

#### Session Update
```sql
UPDATE radacct SET
    acctupdatetime = FROM_UNIXTIME(%{integer:Event-Timestamp}),
    acctinterval = %{integer:Event-Timestamp} - UNIX_TIMESTAMP(acctupdatetime),
    framedipaddress = '%{Framed-IP-Address}',
    acctsessiontime = %{Acct-Session-Time},
    acctinputoctets = %{(uint64:Acct-Input-Gigawords << 32) | uint64:Acct-Input-Octets},
    acctoutputoctets = %{(uint64:Acct-Output-Gigawords << 32) | uint64:Acct-Output-Octets},
    class = '%{Class}'
WHERE acctuniqueid = '%{Acct-Unique-Session-Id}';
```

#### Session Stop
```sql
UPDATE radacct SET
    acctstoptime = FROM_UNIXTIME(%{integer:Event-Timestamp}),
    acctsessiontime = %{Acct-Session-Time},
    acctinputoctets = %{(uint64:Acct-Input-Gigawords << 32) | uint64:Acct-Input-Octets},
    acctoutputoctets = %{(uint64:Acct-Output-Gigawords << 32) | uint64:Acct-Output-Octets},
    acctterminatecause = '%{Acct-Terminate-Cause}',
    connectinfo_stop = '%{Connect-Info}',
    class = '%{Class}'
WHERE acctuniqueid = '%{Acct-Unique-Session-Id}';
```

#### Accounting-On/Off Queries
```sql
-- Handle NAS restart (Accounting-On)
UPDATE radacct SET
    acctstoptime = FROM_UNIXTIME(%{integer:Event-Timestamp}),
    acctsessiontime = %{integer:Event-Timestamp} - UNIX_TIMESTAMP(acctstarttime),
    acctterminatecause = '%{Acct-Terminate-Cause}'
WHERE acctstoptime IS NULL
AND nasipaddress = '%{NAS-IP-Address}'
AND acctstarttime <= FROM_UNIXTIME(%{integer:Event-Timestamp});
```

### 2. Post-Authentication Logging

SQL-based logging of authentication attempts.

**Database Schema:**
```sql
CREATE TABLE radpostauth (
    id int(11) NOT NULL auto_increment,
    username varchar(64) NOT NULL default '',
    pass varchar(64) NOT NULL default '',
    reply varchar(32) NOT NULL default '',
    authdate timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    class varchar(64) NOT NULL default '',
    PRIMARY KEY (id)
);
```

**Post-Auth Queries:**
```sql
-- Log successful authentication
INSERT INTO radpostauth (username, pass, reply, class)
VALUES (
    '%{SQL-User-Name}',
    '%{User-Password}',
    '%{reply:Packet-Type}',
    '%{reply:Class}'
);

-- Log failed authentication
INSERT INTO radpostauth (username, pass, reply, class)
VALUES (
    '%{SQL-User-Name}',
    '%{User-Password}',
    '%{reply:Packet-Type}',
    '%{reply:Class}'
);
```

### 3. Chargeable User Identity (CUI) Tracking

SQL-based tracking of chargeable user identities for compliance and billing.

**Database Schema:**
```sql
CREATE TABLE radcui (
    clientipaddress varchar(15) NOT NULL default '',
    callingstationid varchar(50) NOT NULL default '',
    username varchar(64) NOT NULL default '',
    cui varchar(32) NOT NULL default '',
    lastaccounting datetime NOT NULL default '0000-00-00 00:00:00',
    PRIMARY KEY (clientipaddress, callingstationid)
);
```

**CUI Queries:**
```sql
-- Insert or update CUI on authentication
INSERT INTO radcui (clientipaddress, callingstationid, username, cui, lastaccounting)
VALUES (
    '%{Net.Src.IP}', '%{Calling-Station-Id}',
    '%{User-Name}', '%{reply:Chargeable-User-Identity}', NULL
)
ON DUPLICATE KEY UPDATE
    lastaccounting = '0000-00-00 00:00:00',
    cui = '%{reply:Chargeable-User-Identity}';

-- Update CUI on accounting
UPDATE radcui SET
    lastaccounting = CURRENT_TIMESTAMP
WHERE clientipaddress = '%{Net.Src.IP}'
AND callingstationid = '%{Calling-Station-Id}'
AND username = '%{User-Name}'
AND cui = '%{Chargeable-User-Identity}';
```

### 4. IP Address Pool Management

SQL-based IP address pool management for dynamic IP assignment.

**Database Schema:**
```sql
CREATE TABLE fr_ippool (
    id int unsigned NOT NULL auto_increment,
    pool_name varchar(30) NOT NULL,
    address varchar(43) NOT NULL DEFAULT '',
    owner varchar(128) NOT NULL DEFAULT '',
    gateway varchar(128) NOT NULL DEFAULT '',
    expiry_time DATETIME NOT NULL DEFAULT NOW(),
    status ENUM('dynamic', 'static', 'declined', 'disabled') DEFAULT 'dynamic',
    counter int unsigned NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY fr_ippool_poolname_expire (pool_name, expiry_time),
    KEY address (address),
    KEY fr_ippool_poolname_poolkey_ipaddress (pool_name, owner, address)
);
```

**IP Pool Queries:**
```sql
-- Allocate existing IP for user
SELECT address FROM fr_ippool
WHERE pool_name = '%{Pool-Name}'
AND owner = '%{User-Name}'
AND status IN ('dynamic', 'static')
ORDER BY expiry_time DESC
LIMIT 1;

-- Allocate new IP from pool
SELECT address FROM fr_ippool
WHERE pool_name = '%{Pool-Name}'
AND expiry_time < NOW()
AND status = 'dynamic'
ORDER BY expiry_time
LIMIT 1;

-- Update IP allocation
UPDATE fr_ippool SET
    gateway = '%{NAS-IP-Address}',
    owner = '%{User-Name}',
    expiry_time = NOW() + INTERVAL 3600 SECOND
WHERE address = '%{Framed-IP-Address}'
AND pool_name = '%{Pool-Name}';

-- Release IP address
UPDATE fr_ippool SET
    gateway = '',
    owner = '',
    expiry_time = NOW()
WHERE pool_name = '%{Pool-Name}'
AND owner = '%{User-Name}'
AND address = '%{Framed-IP-Address}';
```

## Advanced SQL Features

### 1. Connection Pool Management

```
sql {
    pool {
        start = 5          # Initial connections
        min = 3            # Minimum connections
        max = 32           # Maximum connections
        spare = 3          # Spare connections
        uses = 1000        # Uses per connection
        lifetime = 0       # Connection lifetime (0 = infinite)
        idle_timeout = 60  # Idle timeout in seconds
        connecting = 2     # Concurrent connection attempts
    }
}
```

### 2. Database Failover

```
sql primary {
    server = "db1.example.com"
    # Primary database configuration
}

sql secondary {
    server = "db2.example.com"
    # Secondary database configuration
}

# Use in virtual server
recv Access-Request {
    primary
    if (fail) {
        secondary
    }
}
```

### 3. Query Optimization

```
sql {
    # Enable query caching
    cache_groups = yes

    # Log queries for debugging
    logfile = ${logdir}/sqllog.sql

    # Set query timeout
    query_timeout = 5

    # Use prepared statements (driver dependent)
    auto_escape = yes
}
```

### 4. Custom SQL Operators

Available operators for check items:
- `==`: Equal (exact match)
- `!=`: Not equal
- `:=`: Always matches, sets attribute
- `+=`: Always matches, adds to attribute list
- `=~`: Regular expression match
- `!~`: Regular expression non-match
- `>`, `>=`, `<`, `<=`: Numeric comparisons
- `=*`: Attribute exists
- `!*`: Attribute doesn't exist

### 5. Advanced Accounting Features

#### Session Tracking
```sql
-- Active sessions query
SELECT username, acctsessionid, acctstarttime, nasipaddress
FROM radacct
WHERE acctstoptime IS NULL;

-- Session duration statistics
SELECT username,
       AVG(acctsessiontime) as avg_session,
       MAX(acctsessiontime) as max_session,
       COUNT(*) as session_count
FROM radacct
WHERE acctstoptime IS NOT NULL
GROUP BY username;
```

#### Bandwidth Monitoring
```sql
-- Bandwidth usage report
SELECT username,
       SUM(acctinputoctets) as total_download,
       SUM(acctoutputoctets) as total_upload,
       SUM(acctinputoctets + acctoutputoctets) as total_transfer
FROM radacct
WHERE acctstarttime >= DATE_SUB(NOW(), INTERVAL 1 MONTH)
GROUP BY username
ORDER BY total_transfer DESC;
```

#### Billing Calculations
```sql
-- Monthly billing data
SELECT username,
       COUNT(*) as sessions,
       SUM(acctsessiontime) as total_time,
       SUM(acctinputoctets + acctoutputoctets) as total_bytes,
       DATE_FORMAT(acctstarttime, '%Y-%m') as billing_month
FROM radacct
WHERE acctstarttime >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
GROUP BY username, billing_month
ORDER BY billing_month DESC, total_bytes DESC;
```

## Performance Optimization

### 1. Database Indexing

```sql
-- Essential indexes for performance
CREATE INDEX idx_radacct_username ON radacct(username);
CREATE INDEX idx_radacct_nasipaddress ON radacct(nasipaddress);
CREATE INDEX idx_radacct_acctstarttime ON radacct(acctstarttime);
CREATE INDEX idx_radacct_acctstoptime ON radacct(acctstoptime);
CREATE INDEX idx_radacct_active_sessions ON radacct(username, acctstoptime);
CREATE INDEX idx_radcheck_username ON radcheck(username);
CREATE INDEX idx_radreply_username ON radreply(username);
CREATE INDEX idx_radusergroup_username ON radusergroup(username);
CREATE INDEX idx_radgroupcheck_groupname ON radgroupcheck(groupname);
CREATE INDEX idx_radgroupreply_groupname ON radgroupreply(groupname);
```

### 2. Query Optimization

```sql
-- Optimized session lookup
SELECT * FROM radacct
WHERE username = 'john'
AND acctstoptime IS NULL
LIMIT 1;

-- Optimized accounting cleanup
DELETE FROM radacct
WHERE acctstoptime < DATE_SUB(NOW(), INTERVAL 1 YEAR)
LIMIT 1000;
```

### 3. Connection Optimization

```
sql {
    # Optimize for high-concurrency environments
    pool {
        start = 10
        min = 5
        max = 100
        spare = 10
        uses = 0
        lifetime = 3600
        idle_timeout = 300
        connecting = 5
    }

    # Use connection compression
    driver = "${dialect}"
    mysql {
        warnings = auto
        tls {
            enable = yes
            compress = yes
        }
    }
}
```

## Security Considerations

### 1. Database Security

```sql
-- Create dedicated RADIUS database user
CREATE USER 'radius'@'localhost' IDENTIFIED BY 'strong_password';

-- Grant minimal required privileges
GRANT SELECT, INSERT, UPDATE, DELETE ON radius.* TO 'radius'@'localhost';

-- Revoke unnecessary privileges
REVOKE DROP, CREATE, ALTER ON radius.* FROM 'radius'@'localhost';
```

### 2. Password Security

```sql
-- Use hashed passwords
INSERT INTO radcheck (username, attribute, op, value)
VALUES ('john', 'Password.Crypt', ':=', '$1$salthere$hashedpassword');

-- Use NT-Password for MSCHAP
INSERT INTO radcheck (username, attribute, op, value)
VALUES ('john', 'NT-Password', ':=', 'nthash_here');
```

### 3. Access Control

```sql
-- Time-based access control
INSERT INTO radcheck (username, attribute, op, value)
VALUES ('john', 'Login-Time', ':=', 'Mo-Fr0900-1700');

-- NAS-based access control
INSERT INTO radcheck (username, attribute, op, value)
VALUES ('john', 'NAS-IP-Address', '==', '192.168.1.1');
```

## Best Practices

### 1. Database Maintenance

```sql
-- Regular cleanup procedures
DELETE FROM radacct WHERE acctstoptime < DATE_SUB(NOW(), INTERVAL 1 YEAR);
DELETE FROM radpostauth WHERE authdate < DATE_SUB(NOW(), INTERVAL 6 MONTH);

-- Archive old data
CREATE TABLE radacct_archive LIKE radacct;
INSERT INTO radacct_archive SELECT * FROM radacct
WHERE acctstoptime < DATE_SUB(NOW(), INTERVAL 1 YEAR);
```

### 2. Monitoring and Alerting

```sql
-- Monitor active sessions
SELECT COUNT(*) as active_sessions FROM radacct WHERE acctstoptime IS NULL;

-- Monitor authentication failures
SELECT COUNT(*) as failed_auths FROM radpostauth
WHERE reply = 'Access-Reject'
AND authdate > DATE_SUB(NOW(), INTERVAL 1 HOUR);
```

### 3. Backup and Recovery

```bash
# Database backup
mysqldump -u root -p radius > radius_backup_$(date +%Y%m%d).sql

# Point-in-time recovery
mysqlbinlog --start-datetime="2024-01-01 00:00:00" \
           --stop-datetime="2024-01-01 23:59:59" \
           /var/log/mysql/mysql-bin.000001 | mysql -u root -p radius
```

This comprehensive documentation covers all major AAA methods in FreeRADIUS with detailed focus on SQL-based implementations. The SQL methods provide the most flexibility and scalability for enterprise deployments, offering centralized user management, detailed accounting, and extensive customization options through database queries and schema design.
