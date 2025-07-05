# FreeRADIUS Logging Documentation

## Overview

This document provides detailed information about logging capabilities in FreeRADIUS based on the official documentation. FreeRADIUS offers comprehensive logging mechanisms for Authentication, Authorization, and Accounting (AAA) processes, with support for various storage backends including SQL databases.

## Main Logging Components

### 1. Main Daemon Logging
- **Configuration**: Located in `raddb/radiusd.conf`
- **Purpose**: Global server events, client connection attempts, slow requests, and server faults
- **Destinations**:
  - File logging
  - Syslog
  - stdout/stderr (debug mode)

### 2. Module-Based Logging
FreeRADIUS provides several specialized logging modules:

#### a) Linelog Module (`rlm_linelog`)
- **Purpose**: Line-based text logging with flexible formatting
- **Features**:
  - Multiple destination support (file, syslog, TCP/UDP sockets, UNIX sockets)
  - Dynamic message formatting based on packet attributes
  - Reference-based message selection
  - Custom delimiters and headers
  - Connection pooling for network destinations

**Configuration Example**:
```
linelog {
    format = "This is a log message for %{User-Name}"
    reference = "messages.%{reply.Packet-Type || 'default'}"
    messages {
        default = "Unknown packet type %{Packet-Type}"
        Access-Accept = "Sent accept: %{User-Name}"
        Access-Reject = "Sent reject: %{User-Name}"
        Access-Challenge = "Sent challenge: %{User-Name}"
    }
    destination = file
    file {
        filename = ${logdir}/linelog
        permissions = 0600
    }
}
```

#### b) Detail Module (`rlm_detail`)
- **Purpose**: Detailed packet-level logging, primarily for accounting
- **Features**:
  - Complete packet attribute logging
  - Daily/hourly file rotation
  - Customizable headers and suppression lists
  - File locking support
  - Escape filename handling

**Configuration Example**:
```
detail {
    filename = "${radacctdir}/%{Net.Src.IP}/detail-%Y-%m-%d"
    permissions = 0600
    header = "%t"
    suppress {
        User-Password
    }
}
```

#### c) Logtee Module (`rlm_logtee`)
- **Purpose**: Runtime request logging with tee functionality
- **Features**:
  - Sends logging to additional destinations
  - Ring buffer for message queuing
  - Multiple transport support (TCP, UDP, UNIX sockets)
  - Real-time log forwarding

**Configuration Example**:
```
logtee {
    format = "%{Log-Type} - %{Log-Level} - %{Log-Message}"
    buffer_depth = 1000000
    destination = 'tcp'
    tcp {
        server = "example.org"
        port = 514
    }
}
```

## AAA Logging

### Authentication Logging
FreeRADIUS provides comprehensive authentication logging through various mechanisms:

#### 1. Authentication Success/Failure Logging
Pre-configured linelog instances for authentication events:

**Access-Accept Logging**:
```
linelog log_auth_access_accept {
    format = "Login OK: [%{User-Name}] (from %client(shortname) port %{NAS-Port} cli %{Calling-Station-Id})"
    destination = ${log.destination}
    syslog {
        facility = ${log.syslog_facility}
        severity = notice
    }
}
```

**Access-Reject Logging**:
```
linelog log_auth_access_reject {
    format = "Login incorrect (%{Module-Failure-Message}): [%{User-Name}] (from %client(shortname) port %{NAS-Port} cli %{Calling-Station-Id})"
    destination = ${log.destination}
    syslog {
        facility = ${log.syslog_facility}
        severity = notice
    }
}
```

#### 2. EAP Session Logging
For complex authentication protocols like EAP, FreeRADIUS supports:
- Initial EAP request logging
- Inner/outer username tracking
- Session state management
- Multi-round trip logging

**Example EAP Logging Configuration**:
```
authorize {
    if (!session-state.) {
        update session-state {
            Tmp-String-1 := "request"
        }
        linelog
    }
}
```

### Authorization Logging
- **Module Integration**: Authorization events are logged through the SQL module and custom linelog configurations
- **Attribute Logging**: Tracks check items, reply items, and group memberships
- **Policy Decisions**: Logs policy evaluation results and attribute assignments

### Accounting Logging
Comprehensive accounting logging for session tracking and billing:

#### 1. Accounting Module Integration
```
linelog log_accounting {
    destination = file
    file {
        filename = ${logdir}/linelog-accounting
        permissions = 0600
    }
    reference = "Accounting-Request.%{Acct-Status-Type || 'unknown'}"
    Accounting-Request {
        Start = "Connect: [%{User-Name}] (did %{Called-Station-Id} cli %{Calling-Station-Id} port %{NAS-Port} ip %{Framed-IP-Address})"
        Stop = "Disconnect: [%{User-Name}] (did %{Called-Station-Id} cli %{Calling-Station-Id} port %{NAS-Port} ip %{Framed-IP-Address}) %{Acct-Session-Time} seconds"
        Interim-Update = ""
        Accounting-On = "NAS %{Net.Src.IP} (%{NAS-IP-Address || NAS-IPv6-Address}) just came online"
        Accounting-Off = "NAS %{Net.Src.IP} (%{NAS-IP-Address || NAS-IPv6-Address}) just went offline"
    }
}
```

#### 2. Accounting Status Types
- **Start**: Session initiation
- **Stop**: Session termination
- **Interim-Update**: Periodic session updates
- **Accounting-On/Off**: NAS status changes

## SQL Database Logging

### 1. SQL Module Configuration
The SQL module (`rlm_sql`) provides comprehensive database logging capabilities:

#### Basic Configuration
```
sql {
    dialect = "mysql"  # or postgresql, sqlite, oracle, etc.
    driver = "${dialect}"
    server = "localhost"
    port = 3306
    login = "radius"
    password = "radpass"
    radius_db = "radius"

    # Accounting tables
    acct_table1 = "radacct"
    acct_table2 = "radacct"
    postauth_table = "radpostauth"

    # Authorization tables
    authcheck_table = "radcheck"
    groupcheck_table = "radgroupcheck"
    authreply_table = "radreply"
    groupreply_table = "radgroupreply"
    usergroup_table = "radusergroup"
}
```

#### Connection Pooling
```
pool {
    start = 0
    min = 1
    max = 100
    connecting = 2
    uses = 0
    lifetime = 0
    request {
        free_delay = 10
    }
}
```

### 2. Database Schema
FreeRADIUS uses a standardized database schema:

#### Core Tables
- **radacct**: Accounting records (session data)
- **radpostauth**: Post-authentication logging
- **radcheck**: User-specific check items
- **radreply**: User-specific reply items
- **radgroupcheck**: Group-specific check items
- **radgroupreply**: Group-specific reply items
- **radusergroup**: User-group membership

#### Accounting Table Structure
The `radacct` table typically includes:
- `radacctid`: Unique session identifier
- `acctsessionid`: NAS session identifier
- `acctuniqueid`: Unique accounting identifier
- `username`: User account name
- `realm`: Authentication realm
- `nasipaddress`: NAS IP address
- `nasportid`: NAS port identifier
- `acctstarttime`: Session start time
- `acctupdatetime`: Last update time
- `acctstoptime`: Session stop time
- `acctsessiontime`: Total session duration
- `acctinputoctets`: Input bytes
- `acctoutputoctets`: Output bytes
- `calledstationid`: Called station identifier
- `callingstationid`: Calling station identifier
- `acctterminatecause`: Session termination reason
- `framedipaddress`: Assigned IP address

### 3. SQL Logging Queries
FreeRADIUS uses configurable SQL queries for different logging operations:

#### Accounting Queries
Located in `sql/<driver>/main/queries.conf`:
- **accounting_start_query**: Log session start
- **accounting_stop_query**: Log session stop
- **accounting_update_query**: Log interim updates
- **accounting_on_query**: Log NAS startup
- **accounting_off_query**: Log NAS shutdown

#### Post-Authentication Queries
- **postauth_query**: Log authentication results
- **postauth_query_reject**: Log authentication failures

### 4. SQL Logging Features

#### Simultaneous Session Tracking
- **Purpose**: Enforce concurrent session limits
- **Implementation**: Uses `radacct` table to track active sessions
- **Configuration**: Requires proper accounting query configuration

#### Detailed Session Information
- **Bandwidth Accounting**: Input/output octets and packets
- **Session Duration**: Precise timing information
- **Connection Details**: NAS information, port details, IP assignments
- **Authentication Context**: Realm, method, client information

#### Query Logging
- **Debug Feature**: Log SQL queries to file
- **Configuration**:
  ```
  sql {
      logfile = ${logdir}/sqllog.sql
  }
  ```

## Monitoring and Statistics

### 1. Log Analysis
FreeRADIUS logs provide extensive information for:
- **Performance Monitoring**: Request processing times, database query performance
- **Security Analysis**: Authentication failures, unusual access patterns
- **Capacity Planning**: Connection pool usage, request volume trends
- **Compliance**: Detailed audit trails for regulatory requirements

### 2. Common Log Patterns
- **Connection Pool Messages**: Opening/closing database connections
- **Client Authentication**: Unknown client warnings
- **Database Issues**: Deadlock detection, connection failures
- **Performance Indicators**: Slow query warnings, high load alerts

### 3. Integration with External Systems
- **Syslog Integration**: Forward logs to centralized logging systems
- **Database Analytics**: Query accounting data for reporting
- **Monitoring Tools**: Integration with Munin, Nagios, etc.
- **Log Management**: Elasticsearch, Graylog, Splunk integration

## Best Practices

### 1. Security Considerations
- **Sensitive Data**: Use suppression lists to exclude passwords from logs
- **File Permissions**: Restrict log file access (0600 permissions)
- **Database Security**: Secure database connections and credentials
- **Log Rotation**: Implement proper log rotation to manage disk space

### 2. Performance Optimization
- **Connection Pooling**: Configure appropriate pool sizes
- **Async Queries**: Use asynchronous database drivers when available
- **Log Levels**: Use appropriate verbosity levels for production
- **Database Indexes**: Ensure proper indexing of accounting tables

### 3. Compliance and Auditing
- **Retention Policies**: Implement log retention according to regulations
- **Audit Trails**: Maintain comprehensive authentication and authorization logs
- **Data Integrity**: Use database constraints and validation
- **Backup Procedures**: Regular backup of log data and databases

## Troubleshooting

### Common Issues
1. **Database Connection Problems**: Check connection parameters and network connectivity
2. **Slow Performance**: Analyze query execution times and optimize database
3. **Missing Log Data**: Verify module configurations and file permissions
4. **Disk Space**: Monitor log file growth and implement rotation

### Debug Procedures
1. **Enable Debug Logging**: Use `-X` flag for detailed output
2. **SQL Query Logging**: Enable `logfile` directive for SQL debugging
3. **Module-Specific Debugging**: Use per-module debug configurations
4. **Network Analysis**: Use `radsniff` for packet-level debugging

This comprehensive logging framework in FreeRADIUS provides administrators with the tools necessary to maintain secure, compliant, and well-monitored AAA infrastructure while supporting various storage backends including SQL databases for enterprise-grade deployments.
