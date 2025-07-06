# FreeRADIUS CoA/Disconnect Implementation Guide

## Overview

This document provides a complete implementation guide for Change of Authorization (CoA) and Disconnect capabilities in FreeRADIUS, specifically tailored for your current MikroTik NAS environment and database schema. This will enable dynamic bandwidth changes without disconnecting users.

## Table of Contents

1. [CoA Architecture Overview](#coa-architecture-overview)
2. [FreeRADIUS CoA Configuration](#freeradius-coa-configuration)
3. [MikroTik Integration](#mikrotik-integration)
4. [Database Integration for Dynamic Triggers](#database-integration-for-dynamic-triggers)
5. [Session Management](#session-management)
6. [Implementation Steps](#implementation-steps)
7. [Testing and Validation](#testing-and-validation)
8. [Error Handling and Monitoring](#error-handling-and-monitoring)
9. [Performance Optimization](#performance-optimization)
10. [Troubleshooting](#troubleshooting)

## CoA Architecture Overview

### RFC 3576 - Dynamic Authorization Extensions

Change of Authorization (CoA) allows dynamic modification of session parameters without disconnecting the user. The protocol uses:

- **CoA-Request** (Packet-Type 43): Request to change session parameters
- **CoA-ACK** (Packet-Type 44): Successful change acknowledgment
- **CoA-NAK** (Packet-Type 45): Change failed/rejected
- **Disconnect-Request** (Packet-Type 40): Request to terminate session
- **Disconnect-ACK** (Packet-Type 41): Successful disconnect
- **Disconnect-NAK** (Packet-Type 42): Disconnect failed/rejected

### Your Current Architecture with CoA

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Interface │    │   FreeRADIUS     │    │   MikroTik      │
│   Service Plan  │───▶│   Server         │───▶│   NAS Device    │
│   Management    │    │   CoA Client     │    │   CoA Server    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   MySQL         │    │   Session        │    │   Active User   │
│   wr_users      │    │   Tracking       │    │   Sessions      │
│   wr_service_*  │    │   radacct        │    │   Rate Limits   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## FreeRADIUS CoA Configuration

### 1. Enable CoA Virtual Server

Create/Enable the CoA virtual server:

**File: `/etc/freeradius/3.0/sites-available/coa`**
```
server coa {
    namespace = radius

    # Listen for CoA and Disconnect requests
    listen {
        type = CoA-Request
        type = Disconnect-Request

        transport = udp

        udp {
            ipaddr = *
            port = 3799
        }
    }

    # Receive CoA Request
    recv CoA-Request {
        # Validate the request attributes
        if (!&User-Name && !&Acct-Session-Id) {
            update reply {
                Reply-Message := "Missing User-Name or Acct-Session-Id"
            }
            reject
        }

        # Log the CoA request
        update request {
            Module-Failure-Message := "CoA request for %{User-Name:-Unknown} session %{Acct-Session-Id:-Unknown}"
        }
        linelog

        # Accept the CoA request (will be forwarded to NAS)
        ok
    }

    # Send CoA ACK
    send CoA-ACK {
        linelog
        ok
    }

    # Send CoA NAK
    send CoA-NAK {
        linelog
        ok
    }

    # Receive Disconnect Request
    recv Disconnect-Request {
        # Similar validation as CoA
        if (!&User-Name && !&Acct-Session-Id) {
            update reply {
                Reply-Message := "Missing User-Name or Acct-Session-Id"
            }
            reject
        }

        # Log the disconnect request
        update request {
            Module-Failure-Message := "Disconnect request for %{User-Name:-Unknown} session %{Acct-Session-Id:-Unknown}"
        }
        linelog

        ok
    }

    # Send Disconnect ACK
    send Disconnect-ACK {
        linelog
        ok
    }

    # Send Disconnect NAK
    send Disconnect-NAK {
        linelog
        ok
    }
}
```

**Enable the CoA site:**
```bash
cd /etc/freeradius/3.0/sites-enabled
ln -s ../sites-available/coa coa
```

### 2. CoA Module Configuration

**File: `/etc/freeradius/3.0/mods-available/coa`**
```
coa {
    # Default destination for CoA requests
    ipaddr = 127.0.0.1
    port = 3799

    # Connection timeout
    timeout = 3

    # Number of retries
    retries = 3

    # Shared secret (will be overridden per NAS)
    secret = "testing123"
}
```

### 3. Custom CoA Policy for Your Environment

**File: `/etc/freeradius/3.0/policy.d/watni_coa_policy.conf`**
```
# Watni CoA Policy for Service Plan Changes
watni_send_coa {
    # Validate required attributes
    if (!&User-Name) {
        update reply {
            Reply-Message := "CoA Error: Missing User-Name"
        }
        fail
    }

    # Get active sessions for the user
    update request {
        Tmp-String-0 := "%{sql:SELECT GROUP_CONCAT(CONCAT(acctsessionid, ':', nasipaddress) SEPARATOR ',') FROM radacct WHERE username='%{User-Name}' AND acctstoptime IS NULL}"
    }

    if (!&Tmp-String-0 || (&Tmp-String-0 == '')) {
        update reply {
            Reply-Message := "No active sessions found for user %{User-Name}"
        }
        fail
    }

    # Process each active session
    update request {
        Tmp-String-1 := &Tmp-String-0
    }

    # Parse session info and send CoA for each session
    foreach &Tmp-String-1 {
        # Extract session ID and NAS IP (format: sessionid:nasip)
        if (&Foreach-Variable =~ /^([^:]+):(.+)$/) {
            update request {
                Tmp-String-2 := "%{1}"  # Session ID
                Tmp-String-3 := "%{2}"  # NAS IP
            }

            # Send CoA to the specific NAS
            subrequest ::CoA-Request {
                # Set target NAS
                NAS-IP-Address := parent.request.Tmp-String-3

                # Session identification
                User-Name := parent.request.User-Name
                Acct-Session-Id := parent.request.Tmp-String-2

                # Get new service plan attributes
                update request {
                    Tmp-String-4 := "%{sql:SELECT attribute_value FROM wr_service_plan_attributes wspa INNER JOIN wr_users wu ON wu.service_plan_id = wspa.plan_id WHERE wu.username='%{parent.request.User-Name}' AND wspa.attribute_name='Mikrotik-Rate-Limit' AND wspa.is_active=1 LIMIT 1}"
                }

                if (&Tmp-String-4 && (&Tmp-String-4 != '')) {
                    # Add the new rate limit
                    Mikrotik-Rate-Limit := &Tmp-String-4

                    # Send to NAS
                    radius
                }
            }
        }
    }

    ok
}

# Disconnect all sessions for a user
watni_disconnect_user {
    if (!&User-Name) {
        update reply {
            Reply-Message := "Disconnect Error: Missing User-Name"
        }
        fail
    }

    # Get active sessions
    update request {
        Tmp-String-0 := "%{sql:SELECT GROUP_CONCAT(CONCAT(acctsessionid, ':', nasipaddress) SEPARATOR ',') FROM radacct WHERE username='%{User-Name}' AND acctstoptime IS NULL}"
    }

    if (!&Tmp-String-0 || (&Tmp-String-0 == '')) {
        update reply {
            Reply-Message := "No active sessions found for user %{User-Name}"
        }
        fail
    }

    # Process each session for disconnect
    foreach &Tmp-String-0 {
        if (&Foreach-Variable =~ /^([^:]+):(.+)$/) {
            subrequest ::Disconnect-Request {
                NAS-IP-Address := "%{2}"
                User-Name := parent.request.User-Name
                Acct-Session-Id := "%{1}"

                radius
            }
        }
    }

    ok
}
```

## MikroTik Integration

### 1. MikroTik Rate Limit Attribute Format

Your current format: `Mikrotik-Rate-Limit = "5M/5M 8M/8M 3M/3M 10/10 8"`

**Format Breakdown:**
```
"RX-Rate[/TX-Rate] [RX-Burst-Rate[/TX-Burst-Rate] [RX-Burst-Threshold[/TX-Burst-Threshold] [RX-Burst-Time[/TX-Burst-Time] [Priority[/TX-Priority]]]]]"

Example: "5M/5M 8M/8M 3M/3M 10/10 8"
- RX-Rate/TX-Rate: 5M/5M (5 Mbps download/upload)
- RX-Burst-Rate/TX-Burst-Rate: 8M/8M (8 Mbps burst)
- RX-Burst-Threshold/TX-Burst-Threshold: 3M/3M (3 Mbps threshold)
- RX-Burst-Time/TX-Burst-Time: 10/10 (10 seconds)
- Priority/TX-Priority: 8 (priority level)
```

### 2. MikroTik CoA Configuration

**On each MikroTik device, enable CoA:**
```
/radius
set accounting=yes authentication=yes
add address=192.168.2.100 secret=testing123 service=login timeout=3s

/radius incoming
set accept=yes port=3799
add address=192.168.2.100 secret=testing123
```

Replace `192.168.2.100` with your FreeRADIUS server IP.

### 3. Enhanced Service Plan Attributes for MikroTik

**Update your wr_service_plan_attributes table:**
```sql
-- Enhanced attributes for better MikroTik integration
INSERT INTO wr_service_plan_attributes (plan_id, attribute_name, attribute_value, nas_vendor, attribute_type, priority) VALUES

-- Plan 1: 5Mbps with burst
(1, 'Mikrotik-Rate-Limit', '5M/5M 8M/8M 3M/3M 10/10 8', 'mikrotik', 'reply', 1),
(1, 'Session-Timeout', '86400', 'mikrotik', 'reply', 2),
(1, 'Idle-Timeout', '1800', 'mikrotik', 'reply', 3),

-- Plan 2: 10Mbps with burst
(2, 'Mikrotik-Rate-Limit', '10M/10M 15M/15M 6M/6M 10/10 8', 'mikrotik', 'reply', 1),
(2, 'Session-Timeout', '86400', 'mikrotik', 'reply', 2),
(2, 'Idle-Timeout', '1800', 'mikrotik', 'reply', 3),

-- Plan 3: 20Mbps with burst
(3, 'Mikrotik-Rate-Limit', '20M/20M 30M/30M 12M/12M 10/10 8', 'mikrotik', 'reply', 1),
(3, 'Session-Timeout', '86400', 'mikrotik', 'reply', 2),
(3, 'Idle-Timeout', '3600', 'mikrotik', 'reply', 3),

-- Plan 4: 50Mbps with burst
(4, 'Mikrotik-Rate-Limit', '50M/50M 75M/75M 30M/30M 10/10 8', 'mikrotik', 'reply', 1),
(4, 'Session-Timeout', '86400', 'mikrotik', 'reply', 2),
(4, 'Idle-Timeout', '3600', 'mikrotik', 'reply', 3);
```

## Database Integration for Dynamic Triggers

### 1. Enhanced Database Schema for CoA

**Add CoA tracking table:**
```sql
CREATE TABLE wr_coa_requests (
    coa_id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(64) NOT NULL,
    request_type ENUM('coa', 'disconnect') NOT NULL,
    nas_ip_address VARCHAR(15) NOT NULL,
    acct_session_id VARCHAR(64) DEFAULT NULL,
    old_rate_limit VARCHAR(253) DEFAULT NULL,
    new_rate_limit VARCHAR(253) DEFAULT NULL,
    status ENUM('pending', 'sent', 'ack', 'nak', 'timeout', 'failed') DEFAULT 'pending',
    response_message TEXT DEFAULT NULL,
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL DEFAULT NULL,

    PRIMARY KEY (coa_id),
    KEY idx_username (username),
    KEY idx_status_requested (status, requested_at),
    KEY idx_nas_session (nas_ip_address, acct_session_id)
);

-- Add trigger for service plan changes
DELIMITER $$
CREATE TRIGGER tr_service_plan_change
    AFTER UPDATE ON wr_users
    FOR EACH ROW
BEGIN
    -- Check if service_plan_id changed
    IF OLD.service_plan_id != NEW.service_plan_id THEN
        -- Insert CoA request for each active session
        INSERT INTO wr_coa_requests (username, request_type, nas_ip_address, acct_session_id, status)
        SELECT
            NEW.username,
            'coa',
            ra.nasipaddress,
            ra.acctsessionid,
            'pending'
        FROM radacct ra
        WHERE ra.username = NEW.username
          AND ra.acctstoptime IS NULL;
    END IF;
END$$
DELIMITER ;
```

### 2. CoA Processing Script

**File: `/opt/freeradius/scripts/process_coa_queue.php`**
```php
#!/usr/bin/env php
<?php
/**
 * CoA Queue Processor for Watni FreeRADIUS
 * Processes pending CoA requests from database triggers
 */

// Database configuration
$config = [
    'host' => 'localhost',
    'username' => 'radius',
    'password' => 'RadiusPassword123!',
    'database' => 'radius'
];

// FreeRADIUS configuration
$freeradius = [
    'radclient_path' => '/usr/bin/radclient',
    'server_ip' => '127.0.0.1',
    'coa_port' => '3799',
    'secret' => 'testing123'
];

try {
    $pdo = new PDO(
        "mysql:host={$config['host']};dbname={$config['database']}",
        $config['username'],
        $config['password'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );

    // Get pending CoA requests
    $stmt = $pdo->prepare("
        SELECT coa_id, username, request_type, nas_ip_address, acct_session_id
        FROM wr_coa_requests
        WHERE status = 'pending'
        ORDER BY requested_at ASC
        LIMIT 10
    ");
    $stmt->execute();

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        processCoa($pdo, $row, $freeradius);
        usleep(100000); // 100ms delay between requests
    }

} catch (Exception $e) {
    error_log("CoA Processor Error: " . $e->getMessage());
}

function processCoa($pdo, $coaRequest, $config) {
    $username = $coaRequest['username'];
    $nasIp = $coaRequest['nas_ip_address'];
    $sessionId = $coaRequest['acct_session_id'];
    $coaId = $coaRequest['coa_id'];

    try {
        // Mark as being processed
        $updateStmt = $pdo->prepare("UPDATE wr_coa_requests SET status = 'sent' WHERE coa_id = ?");
        $updateStmt->execute([$coaId]);

        if ($coaRequest['request_type'] === 'coa') {
            // Get new rate limit from service plan
            $rateStmt = $pdo->prepare("
                SELECT wspa.attribute_value
                FROM wr_service_plan_attributes wspa
                INNER JOIN wr_users wu ON wu.service_plan_id = wspa.plan_id
                WHERE wu.username = ?
                  AND wspa.attribute_name = 'Mikrotik-Rate-Limit'
                  AND wspa.is_active = 1
                LIMIT 1
            ");
            $rateStmt->execute([$username]);
            $rateLimit = $rateStmt->fetchColumn();

            if (!$rateLimit) {
                throw new Exception("No rate limit found for user $username");
            }

            // Prepare CoA packet
            $packet = "User-Name = \"$username\"\n";
            $packet .= "Acct-Session-Id = \"$sessionId\"\n";
            $packet .= "Mikrotik-Rate-Limit = \"$rateLimit\"\n";

            // Send CoA request
            $result = sendRadiusPacket($packet, $nasIp, 'coa', $config);

            // Update status based on result
            if (strpos($result, 'CoA-ACK') !== false) {
                $updateStmt = $pdo->prepare("
                    UPDATE wr_coa_requests
                    SET status = 'ack', response_message = ?, completed_at = NOW()
                    WHERE coa_id = ?
                ");
                $updateStmt->execute([$result, $coaId]);
                echo "CoA ACK for user $username\n";
            } else {
                $updateStmt = $pdo->prepare("
                    UPDATE wr_coa_requests
                    SET status = 'nak', response_message = ?, completed_at = NOW()
                    WHERE coa_id = ?
                ");
                $updateStmt->execute([$result, $coaId]);
                echo "CoA NAK for user $username: $result\n";
            }
        }

    } catch (Exception $e) {
        // Mark as failed
        $updateStmt = $pdo->prepare("
            UPDATE wr_coa_requests
            SET status = 'failed', response_message = ?, completed_at = NOW()
            WHERE coa_id = ?
        ");
        $updateStmt->execute([$e->getMessage(), $coaId]);
        error_log("CoA processing failed for ID $coaId: " . $e->getMessage());
    }
}

function sendRadiusPacket($packet, $nasIp, $type, $config) {
    $tempFile = tempnam(sys_get_temp_dir(), 'coa_');
    file_put_contents($tempFile, $packet);

    $cmd = sprintf(
        'cat %s | %s -x %s:%s %s %s 2>&1',
        escapeshellarg($tempFile),
        escapeshellarg($config['radclient_path']),
        escapeshellarg($nasIp),
        escapeshellarg($config['coa_port']),
        escapeshellarg($type),
        escapeshellarg($config['secret'])
    );

    $result = shell_exec($cmd);
    unlink($tempFile);

    return $result ?: 'No response';
}
?>
```

### 3. Cron Job for CoA Processing

**Add to crontab:**
```bash
# Process CoA queue every minute
* * * * * /opt/freeradius/scripts/process_coa_queue.php >> /var/log/freeradius/coa_processor.log 2>&1
```

## Session Management

### 1. Enhanced Session Tracking

**Add to your existing site configuration:**
```
# In your default site's recv Accounting-Request section
recv Accounting-Request {
    # ... existing configuration ...

    # Enhanced session tracking for CoA
    if (&Acct-Status-Type == "Start") {
        # Log session start with current rate limit
        update request {
            Tmp-String-0 := "%{sql:SELECT attribute_value FROM wr_service_plan_attributes wspa INNER JOIN wr_users wu ON wu.service_plan_id = wspa.plan_id WHERE wu.username='%{User-Name}' AND wspa.attribute_name='Mikrotik-Rate-Limit' AND wspa.is_active=1 LIMIT 1}"
        }

        if (&Tmp-String-0) {
            # Update radacct with current rate limit
            update request {
                Tmp-String-1 := "%{sql:UPDATE radacct SET class='%{Tmp-String-0}' WHERE acctuniqueid='%{Acct-Unique-Session-Id}'}"
            }
        }
    }

    # ... rest of existing configuration ...
}
```

## Implementation Steps

### Phase 1: Basic CoA Setup (Day 1-2)

1. **Enable CoA Virtual Server:**
   ```bash
   cd /etc/freeradius/3.0/sites-enabled
   ln -s ../sites-available/coa coa
   systemctl restart freeradius
   ```

2. **Test CoA Reception:**
   ```bash
   # Test if FreeRADIUS is listening on CoA port
   netstat -ulnp | grep 3799

   # Send test CoA packet
   echo "User-Name = testuser1" | radclient 127.0.0.1:3799 coa testing123
   ```

3. **Configure MikroTik Devices:**
   ```
   # On each MikroTik router
   /radius incoming
   set accept=yes port=3799
   add address=YOUR_FREERADIUS_IP secret=testing123
   ```

### Phase 2: Database Integration (Day 3-4)

1. **Create CoA Tables:**
   ```sql
   -- Execute the wr_coa_requests table creation
   -- Execute the trigger creation
   ```

2. **Install CoA Processing Script:**
   ```bash
   mkdir -p /opt/freeradius/scripts
   # Copy the PHP script
   chmod +x /opt/freeradius/scripts/process_coa_queue.php
   ```

3. **Setup Cron Job:**
   ```bash
   echo "* * * * * /opt/freeradius/scripts/process_coa_queue.php >> /var/log/freeradius/coa_processor.log 2>&1" | crontab -
   ```

### Phase 3: Integration Testing (Day 5-6)

1. **Test Manual CoA:**
   ```bash
   # Create test packet
   cat << EOF > test_coa.txt
   User-Name = "testuser1"
   Acct-Session-Id = "SESSION_ID_FROM_RADACCT"
   Mikrotik-Rate-Limit = "10M/10M 15M/15M 6M/6M 10/10 8"
   EOF

   # Send to NAS
   cat test_coa.txt | radclient NAS_IP:3799 coa testing123
   ```

2. **Test Database Trigger:**
   ```sql
   -- Change service plan for active user
   UPDATE wr_users SET service_plan_id = 2 WHERE username = 'testuser1';

   -- Check if CoA request was created
   SELECT * FROM wr_coa_requests WHERE username = 'testuser1';
   ```

### Phase 4: Web Interface Integration (Day 7-8)

**Add to your web interface service plan change function:**
```php
// After updating service plan in database
$stmt = $pdo->prepare("
    UPDATE wr_users
    SET service_plan_id = ?
    WHERE username = ?
");
$stmt->execute([$new_plan_id, $username]);

// Trigger immediate CoA processing
exec('/opt/freeradius/scripts/process_coa_queue.php > /dev/null 2>&1 &');
```

## Testing and Validation

### 1. Manual Testing Scripts

**File: `/opt/freeradius/testing/test_coa.sh`**
```bash
#!/bin/bash

USERNAME="testuser1"
NAS_IP="192.168.2.30"
SECRET="testing123"

echo "=== Testing CoA for $USERNAME ==="

# Get active session
SESSION_ID=$(mysql -u radius -pRadiusPassword123! radius -e "SELECT acctsessionid FROM radacct WHERE username='$USERNAME' AND acctstoptime IS NULL LIMIT 1;" -s -N)

if [ -z "$SESSION_ID" ]; then
    echo "No active session found for $USERNAME"
    exit 1
fi

echo "Found session: $SESSION_ID"

# Test CoA with different rate limits
for PLAN in 1 2 3 4; do
    echo "Testing plan $PLAN..."

    RATE_LIMIT=$(mysql -u radius -pRadiusPassword123! radius -e "SELECT attribute_value FROM wr_service_plan_attributes WHERE plan_id=$PLAN AND attribute_name='Mikrotik-Rate-Limit' LIMIT 1;" -s -N)

    cat << EOF | radclient -x $NAS_IP:3799 coa $SECRET
User-Name = "$USERNAME"
Acct-Session-Id = "$SESSION_ID"
Mikrotik-Rate-Limit = "$RATE_LIMIT"
EOF

    echo "Waiting 5 seconds..."
    sleep 5
done
```

### 2. Automated Testing

**File: `/opt/freeradius/testing/automated_coa_test.php`**
```php
#!/usr/bin/env php
<?php
// Test script for automated CoA testing
$config = [
    'host' => 'localhost',
    'username' => 'radius',
    'password' => 'RadiusPassword123!',
    'database' => 'radius'
];

$pdo = new PDO("mysql:host={$config['host']};dbname={$config['database']}",
               $config['username'], $config['password']);

// Test users with active sessions
$users = ['testuser1', 'testuser2', 'testuser3'];

foreach ($users as $username) {
    echo "Testing CoA for $username\n";

    // Get current plan
    $stmt = $pdo->prepare("SELECT service_plan_id FROM wr_users WHERE username = ?");
    $stmt->execute([$username]);
    $currentPlan = $stmt->fetchColumn();

    // Change to next plan (cycle through 1-4)
    $newPlan = ($currentPlan % 4) + 1;

    // Update plan
    $stmt = $pdo->prepare("UPDATE wr_users SET service_plan_id = ? WHERE username = ?");
    $stmt->execute([$newPlan, $username]);

    echo "Changed $username from plan $currentPlan to plan $newPlan\n";

    // Wait for CoA processing
    sleep(10);

    // Check CoA status
    $stmt = $pdo->prepare("SELECT status, response_message FROM wr_coa_requests WHERE username = ? ORDER BY requested_at DESC LIMIT 1");
    $stmt->execute([$username]);
    $result = $stmt->fetch();

    echo "CoA Status: " . ($result['status'] ?? 'No request found') . "\n";
    echo "Response: " . ($result['response_message'] ?? 'N/A') . "\n\n";
}
?>
```

## Error Handling and Monitoring

### 1. Enhanced Logging Configuration

**File: `/etc/freeradius/3.0/mods-available/linelog_coa`**
```
linelog linelog_coa {
    destination = file
    file {
        filename = ${logdir}/coa.log
        permissions = 0640
    }
    format = "%S - %{Module-Failure-Message}"
    reference = "coa.%{%{reply.Packet-Type}:-Unknown}"

    coa {
        CoA-ACK = "CoA-ACK: %{User-Name} session %{Acct-Session-Id} - %{reply.Reply-Message:-Success}"
        CoA-NAK = "CoA-NAK: %{User-Name} session %{Acct-Session-Id} - %{reply.Reply-Message:-Failed}"
        Disconnect-ACK = "Disconnect-ACK: %{User-Name} session %{Acct-Session-Id} - %{reply.Reply-Message:-Success}"
        Disconnect-NAK = "Disconnect-NAK: %{User-Name} session %{Acct-Session-Id} - %{reply.Reply-Message:-Failed}"
        Unknown = "Unknown CoA response: %{reply.Packet-Type} for %{User-Name}"
    }
}
```

### 2. Monitoring Script

**File: `/opt/freeradius/monitoring/coa_monitor.sh`**
```bash
#!/bin/bash

LOGFILE="/var/log/freeradius/coa_monitor.log"
MYSQL_USER="radius"
MYSQL_PASS="RadiusPassword123!"
MYSQL_DB="radius"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOGFILE
}

# Check pending CoA requests
PENDING=$(mysql -u $MYSQL_USER -p$MYSQL_PASS $MYSQL_DB -e "SELECT COUNT(*) FROM wr_coa_requests WHERE status='pending'" -s -N)

if [ "$PENDING" -gt 10 ]; then
    log_message "WARNING: $PENDING pending CoA requests"
fi

# Check failed CoA requests in last hour
FAILED=$(mysql -u $MYSQL_USER -p$MYSQL_PASS $MYSQL_DB -e "SELECT COUNT(*) FROM wr_coa_requests WHERE status='failed' AND requested_at > NOW() - INTERVAL 1 HOUR" -s -N)

if [ "$FAILED" -gt 5 ]; then
    log_message "WARNING: $FAILED failed CoA requests in last hour"
fi

# Check CoA processing queue health
OLDEST_PENDING=$(mysql -u $MYSQL_USER -p$MYSQL_PASS $MYSQL_DB -e "SELECT TIMESTAMPDIFF(MINUTE, MIN(requested_at), NOW()) FROM wr_coa_requests WHERE status='pending'" -s -N)

if [ "$OLDEST_PENDING" -gt 5 ] && [ "$OLDEST_PENDING" != "NULL" ]; then
    log_message "WARNING: Oldest pending CoA request is $OLDEST_PENDING minutes old"
fi

# Log daily statistics
if [ "$(date '+%H:%M')" == "00:00" ]; then
    DAILY_STATS=$(mysql -u $MYSQL_USER -p$MYSQL_PASS $MYSQL_DB -e "
        SELECT
            CONCAT('Daily CoA Stats - Total: ', COUNT(*),
                   ' Success: ', SUM(CASE WHEN status='ack' THEN 1 ELSE 0 END),
                   ' Failed: ', SUM(CASE WHEN status IN ('nak', 'failed') THEN 1 ELSE 0 END))
        FROM wr_coa_requests
        WHERE DATE(requested_at) = CURDATE()
    " -s -N)
    log_message "$DAILY_STATS"
fi
```

**Add to crontab:**
```bash
# Monitor CoA every 5 minutes
*/5 * * * * /opt/freeradius/monitoring/coa_monitor.sh
```

### 3. Web Interface Dashboard

**Add CoA status to your admin dashboard:**
```php
<?php
// CoA Dashboard Widget
function getCoAStats($pdo) {
    $stats = [];

    // Pending requests
    $stmt = $pdo->query("SELECT COUNT(*) FROM wr_coa_requests WHERE status='pending'");
    $stats['pending'] = $stmt->fetchColumn();

    // Success rate last 24 hours
    $stmt = $pdo->query("
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status='ack' THEN 1 ELSE 0 END) as success
        FROM wr_coa_requests
        WHERE requested_at > NOW() - INTERVAL 24 HOUR
    ");
    $result = $stmt->fetch();
    $stats['success_rate'] = $result['total'] > 0 ?
        round(($result['success'] / $result['total']) * 100, 2) : 0;

    // Recent failures
    $stmt = $pdo->query("
        SELECT username, response_message, requested_at
        FROM wr_coa_requests
        WHERE status IN ('nak', 'failed')
          AND requested_at > NOW() - INTERVAL 1 HOUR
        ORDER BY requested_at DESC
        LIMIT 5
    ");
    $stats['recent_failures'] = $stmt->fetchAll();

    return $stats;
}
?>
```

## Performance Optimization

### 1. Database Indexing

```sql
-- Additional indexes for CoA performance
CREATE INDEX idx_radacct_user_active ON radacct(username, acctstoptime);
CREATE INDEX idx_radacct_nas_session ON radacct(nasipaddress, acctsessionid);
CREATE INDEX idx_wr_users_plan_status ON wr_users(service_plan_id, is_enabled, account_status);
CREATE INDEX idx_wr_service_plan_attr_lookup ON wr_service_plan_attributes(plan_id, attribute_name, is_active);
```

### 2. CoA Queue Optimization

**Enhanced processing script with batch processing:**
```php
// In process_coa_queue.php - Replace the main processing loop

// Process in batches for better performance
$batchSize = 20;
$stmt = $pdo->prepare("
    SELECT coa_id, username, request_type, nas_ip_address, acct_session_id
    FROM wr_coa_requests
    WHERE status = 'pending'
    ORDER BY requested_at ASC
    LIMIT ?
");
$stmt->execute([$batchSize]);

$batch = $stmt->fetchAll(PDO::FETCH_ASSOC);
if (empty($batch)) {
    exit(0); // No pending requests
}

// Group by NAS for efficient processing
$byNas = [];
foreach ($batch as $request) {
    $byNas[$request['nas_ip_address']][] = $request;
}

// Process each NAS group
foreach ($byNas as $nasIp => $requests) {
    foreach ($requests as $request) {
        processCoa($pdo, $request, $freeradius);
        usleep(50000); // 50ms delay between requests to same NAS
    }
    usleep(200000); // 200ms delay between different NAS devices
}
```

### 3. Connection Pooling for High Volume

**Enhanced FreeRADIUS SQL configuration for CoA:**
```
sql {
    # ... existing configuration ...

    pool {
        start = 10
        min = 5
        max = 50
        spare = 10
        uses = 1000
        lifetime = 3600
        idle_timeout = 600
        connecting = 5
    }

    # Enable read-write splitting if using MySQL replication
    read_clients = yes
}
```

## Troubleshooting

### 1. Common Issues and Solutions

#### Issue: CoA requests are not being processed

**Diagnosis:**
```bash
# Check if cron job is running
ps aux | grep process_coa_queue
crontab -l | grep coa

# Check pending requests
mysql -u radius -pRadiusPassword123! radius -e "SELECT COUNT(*) FROM wr_coa_requests WHERE status='pending';"

# Check log for errors
tail -f /var/log/freeradius/coa_processor.log
```

**Solution:**
```bash
# Restart cron service
systemctl restart cron

# Manual processing test
/opt/freeradius/scripts/process_coa_queue.php
```

#### Issue: MikroTik not accepting CoA requests

**Diagnosis:**
```bash
# Test CoA manually
echo "User-Name = testuser1" | radclient -x MIKROTIK_IP:3799 coa testing123

# Check MikroTik logs
# On MikroTik: /log print where topics~"radius"
```

**Solution:**
```
# On MikroTik, verify configuration
/radius incoming print
/radius print

# Ensure correct secret and IP
/radius incoming
set accept=yes port=3799
add address=FREERADIUS_IP secret=testing123
```

#### Issue: High CoA failure rate

**Diagnosis:**
```sql
-- Check failure patterns
SELECT
    nas_ip_address,
    status,
    COUNT(*) as count,
    response_message
FROM wr_coa_requests
WHERE requested_at > NOW() - INTERVAL 1 HOUR
GROUP BY nas_ip_address, status, response_message;
```

**Solution:**
- Verify NAS connectivity and shared secrets
- Check for network congestion
- Adjust CoA timeout values
- Implement retry logic with exponential backoff

### 2. Debug Mode Testing

**Enable debug mode for CoA:**
```bash
# Stop FreeRADIUS
systemctl stop freeradius

# Run in debug mode
freeradius -X | grep -i coa
```

### 3. Network Troubleshooting

**Packet capture for CoA debugging:**
```bash
# Capture CoA traffic
tcpdump -i any -n port 3799 -A

# Test connectivity to each NAS
for nas in 192.168.2.30 192.168.2.31 192.168.2.32 192.168.2.33; do
    echo "Testing $nas..."
    nc -u -w 3 $nas 3799 < /dev/null && echo "Port 3799 open" || echo "Port 3799 closed"
done
```

## Conclusion

This implementation provides a complete, production-ready CoA solution that integrates seamlessly with your existing FreeRADIUS and MikroTik infrastructure. The solution includes:

- **Automated CoA processing** triggered by database changes
- **Comprehensive error handling** and monitoring
- **Performance optimization** for high-volume environments
- **Complete testing framework** for validation
- **Integration with your existing** service plan management system

### Next Steps

1. **Phase 1**: Implement basic CoA configuration and test manually
2. **Phase 2**: Deploy database triggers and automated processing
3. **Phase 3**: Integrate with web interface for real-time plan changes
4. **Phase 4**: Implement advanced monitoring and alerting

The solution is designed to scale with your growing user base while maintaining the reliability and performance requirements of your ISP infrastructure.
