"""Build personas/finance_server.json deterministically.

Finance production server persona: Ubuntu 20.04 LTS running PostgreSQL 14
and a Java Spring Boot payment-processing service. ~90 days uptime, strict
permissions, audit-log trails, a cron-driven nightly backup job, and CSV
extracts of fake transaction data. This is the high-threat escalation
persona — what a persistent, sophisticated attacker sees after their
threat score crosses the critical threshold.

Usage:  python scripts/build_finance_server_persona.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from honeypot.persona_validator import validate  # noqa: E402


# ---------------------------------------------------------------------------
# Time anchors — a long-lived production box
# ---------------------------------------------------------------------------
INSTALL       = "2024-05-18T09:00:00Z"
LAST_UPDATE   = "2026-01-17T03:14:22Z"   # last apt upgrade, months ago
LAST_BOOT     = "2026-01-17T03:22:40Z"   # rebooted after kernel update
RECENT_LOG    = "2026-04-15T23:58:59Z"
NIGHTLY_BATCH = "2026-04-16T02:00:04Z"   # cron ran at 02:00, two before "now"
Q1_REPORT     = "2026-04-01T02:00:17Z"

# now = 2026-04-16 12:00 UTC → ~89.4 days since LAST_BOOT
UPTIME_SECONDS = 7_724_240


# ---------------------------------------------------------------------------
# /etc file contents
# ---------------------------------------------------------------------------

HOSTNAME_TXT = "fin-db-prod-01\n"

HOSTS_TXT = (
    "127.0.0.1\tlocalhost\n"
    "127.0.1.1\tfin-db-prod-01\n"
    "\n"
    "10.20.4.11\tfin-db-prod-01.prod.acmecorp.internal fin-db-prod-01\n"
    "10.20.4.12\tfin-db-replica-01.prod.acmecorp.internal fin-db-replica-01\n"
    "10.20.4.20\tfin-audit.prod.acmecorp.internal fin-audit\n"
    "\n"
    "::1\tlocalhost ip6-localhost ip6-loopback\n"
    "ff02::1\tip6-allnodes\n"
    "ff02::2\tip6-allrouters\n"
)

OS_RELEASE_TXT = (
    'NAME="Ubuntu"\n'
    'VERSION="20.04.6 LTS (Focal Fossa)"\n'
    "ID=ubuntu\n"
    "ID_LIKE=debian\n"
    'PRETTY_NAME="Ubuntu 20.04.6 LTS"\n'
    'VERSION_ID="20.04"\n'
    'HOME_URL="https://www.ubuntu.com/"\n'
    'SUPPORT_URL="https://help.ubuntu.com/"\n'
    'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
    'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
    "VERSION_CODENAME=focal\n"
    "UBUNTU_CODENAME=focal\n"
)

PASSWD_TXT = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
    "messagebus:x:102:105::/nonexistent:/usr/sbin/nologin\n"
    "syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n"
    "sshd:x:108:65534::/run/sshd:/usr/sbin/nologin\n"
    "postgres:x:107:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
    "finapp:x:1002:1002:Finance Application Service,,,:/home/finapp:/bin/bash\n"
)

SHADOW_TXT = (
    "root:!:19860:0:99999:7:::\n"
    "daemon:*:19860:0:99999:7:::\n"
    "bin:*:19860:0:99999:7:::\n"
    "sys:*:19860:0:99999:7:::\n"
    "sync:*:19860:0:99999:7:::\n"
    "www-data:*:19860:0:99999:7:::\n"
    "nobody:*:19860:0:99999:7:::\n"
    "systemd-resolve:*:19860:0:99999:7:::\n"
    "messagebus:*:19860:0:99999:7:::\n"
    "syslog:*:19860:0:99999:7:::\n"
    "sshd:*:19860:0:99999:7:::\n"
    "postgres:!:19860:0:99999:7:::\n"
    "finapp:$6$aB9cD2eF$hG7kL0mN3pQ5rS8tU1vW4xY6zA9bC2dE5fH8iJ0kL3mN6oP9qR:19860:0:99999:7:::\n"
)

GROUP_TXT = (
    "root:x:0:\n"
    "daemon:x:1:\n"
    "bin:x:2:\n"
    "sys:x:3:\n"
    "adm:x:4:syslog\n"
    "sudo:x:27:finapp\n"
    "www-data:x:33:\n"
    "postgres:x:113:\n"
    "ssl-cert:x:114:postgres\n"
    "nogroup:x:65534:\n"
    "finapp:x:1002:\n"
)


# ---------------------------------------------------------------------------
# finapp home — service account running the Spring Boot app
# ---------------------------------------------------------------------------

BASH_HISTORY_FINAPP = (
    "cd /home/finapp\n"
    "tail -f logs/finapp.log\n"
    "psql -h localhost -U finapp_ro -d finance_prod\n"
    "java -jar finapp.jar --spring.profiles.active=prod\n"
    "ls reports/\n"
    "cat config/database.yml\n"
    "systemctl status finapp.service\n"
    "exit\n"
)

BASHRC_FINAPP = (
    "# ~/.bashrc for finapp service account\n"
    "case $- in\n"
    "    *i*) ;;\n"
    "      *) return;;\n"
    "esac\n"
    "\n"
    "HISTCONTROL=ignoreboth\n"
    "HISTSIZE=2000\n"
    "\n"
    "export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64\n"
    'export PATH="$JAVA_HOME/bin:$PATH"\n'
    "export FINAPP_HOME=/home/finapp\n"
    "export FINAPP_ENV=prod\n"
    "\n"
    "alias ll='ls -alF'\n"
    "alias logs='tail -f /home/finapp/logs/finapp.log'\n"
)

PROFILE_FINAPP = (
    "# ~/.profile\n"
    "if [ -n \"$BASH_VERSION\" ] && [ -f \"$HOME/.bashrc\" ]; then\n"
    "    . \"$HOME/.bashrc\"\n"
    "fi\n"
)

DATABASE_YML = (
    "# /home/finapp/config/database.yml\n"
    "# Managed by ops. DO NOT EDIT by hand — changes roll through ansible.\n"
    "production:\n"
    "  primary:\n"
    "    adapter: postgresql\n"
    "    host: localhost\n"
    "    port: 5432\n"
    "    database: finance_prod\n"
    "    username: finapp_rw\n"
    "    password: pgS3rvice-2026-Q1-rotation\n"
    "    pool: 32\n"
    "    sslmode: require\n"
    "  replica:\n"
    "    adapter: postgresql\n"
    "    host: fin-db-replica-01.prod.acmecorp.internal\n"
    "    port: 5432\n"
    "    database: finance_prod\n"
    "    username: finapp_ro\n"
    "    password: pgReadOnly-2026-Q1-rotation\n"
    "    pool: 16\n"
    "    sslmode: require\n"
)

APPLICATION_YML = (
    "# /home/finapp/config/application.yml\n"
    "spring:\n"
    "  application:\n"
    "    name: finapp\n"
    "  datasource:\n"
    "    url: jdbc:postgresql://localhost:5432/finance_prod?sslmode=require\n"
    "    username: finapp_rw\n"
    "    password: pgS3rvice-2026-Q1-rotation\n"
    "    hikari:\n"
    "      maximum-pool-size: 32\n"
    "      connection-timeout: 5000\n"
    "  jpa:\n"
    "    hibernate:\n"
    "      ddl-auto: validate\n"
    "    properties:\n"
    "      hibernate:\n"
    "        dialect: org.hibernate.dialect.PostgreSQLDialect\n"
    "server:\n"
    "  port: 8443\n"
    "  ssl:\n"
    "    enabled: true\n"
    "    key-store: /home/finapp/config/keystore.p12\n"
    "    key-store-password: finapp-keystore-2026\n"
    "    key-store-type: PKCS12\n"
    "audit:\n"
    "  destination: /home/finapp/logs/audit.log\n"
    "  retention-days: 2555\n"
    "integrations:\n"
    "  swift:\n"
    "    endpoint: https://swift-gateway.prod.acmecorp.internal/v2\n"
    "    api-key: swift_api_prod_fakeonlydoNotUse_x9kL3mN7pQ\n"
    "  plaid:\n"
    "    client-id: 65a3fakelienttidfortest\n"
    "    secret: plaid_prod_fake_do_not_use_this_key_anywhere_real\n"
)

# Q1 fake transactions CSV. Ten rows — enough to look real, small enough
# that the attacker reads every line.
TRANSACTIONS_CSV = (
    "transaction_id,timestamp,account_from,account_to,amount_usd,currency,status,memo\n"
    "txn_000001,2026-01-02T09:14:02Z,ACCT-48201,ACCT-91045,12450.00,USD,settled,wire-in Q1-payroll\n"
    "txn_000002,2026-01-02T11:02:55Z,ACCT-48201,ACCT-10023,875.42,USD,settled,vendor-bill 9921\n"
    "txn_000003,2026-01-15T14:33:18Z,ACCT-55110,ACCT-48201,310200.00,USD,settled,invoice-INV-2026-0041\n"
    "txn_000004,2026-01-18T08:41:01Z,ACCT-48201,ACCT-72300,4890.75,EUR,settled,eu-supplier-payout\n"
    "txn_000005,2026-02-01T00:00:01Z,ACCT-48201,ACCT-10023,182.10,USD,settled,subscription-renewal\n"
    "txn_000006,2026-02-14T16:22:40Z,ACCT-91045,ACCT-48201,58000.00,USD,settled,customer-refund-reversal\n"
    "txn_000007,2026-02-28T23:59:59Z,ACCT-48201,ACCT-55110,994120.50,USD,settled,quarterly-dividend\n"
    "txn_000008,2026-03-05T10:04:12Z,ACCT-48201,ACCT-83092,2210.00,USD,pending,awaiting-swift-ack\n"
    "txn_000009,2026-03-22T07:18:33Z,ACCT-83092,ACCT-48201,12000.00,GBP,settled,fx-hedge-settlement\n"
    "txn_000010,2026-03-31T19:45:28Z,ACCT-48201,ACCT-91045,450.00,USD,settled,expense-reimbursement\n"
)

# finapp.log — a few lines that reference real processes + db users
FINAPP_LOG = (
    "2026-04-16T02:00:04.102Z INFO  c.a.finapp.Scheduler - nightly batch job started\n"
    "2026-04-16T02:00:04.311Z INFO  o.s.orm.jpa.EntityManagerFactoryBuilderImpl - HHH000204: Processing PersistenceUnitInfo\n"
    "2026-04-16T02:01:11.887Z INFO  c.a.finapp.BatchJob - reconciled 4812 transactions for 2026-04-15\n"
    "2026-04-16T02:01:12.001Z INFO  c.a.finapp.AuditSink - wrote 4812 audit events to /home/finapp/logs/audit.log\n"
    "2026-04-16T02:01:12.114Z INFO  c.a.finapp.Scheduler - nightly batch job complete in 67811ms\n"
    "2026-04-16T04:00:00.044Z INFO  c.a.finapp.HealthCheck - db=OK replica=OK swift=OK plaid=OK\n"
    "2026-04-16T08:00:00.028Z INFO  c.a.finapp.HealthCheck - db=OK replica=OK swift=OK plaid=OK\n"
)

AUDIT_LOG = (
    "2026-04-15T23:11:04Z user=finapp_rw action=SELECT table=transactions rows=124 session=a41f\n"
    "2026-04-15T23:12:17Z user=finapp_rw action=INSERT table=transactions rows=1 session=a41f txn_id=txn_021841\n"
    "2026-04-15T23:30:02Z user=finapp_ro action=SELECT table=accounts rows=3 session=b18c\n"
    "2026-04-16T02:01:12Z user=system action=BATCH_RECONCILE rows=4812 job=nightly_reconcile\n"
    "2026-04-16T08:00:00Z user=system action=HEALTHCHECK result=OK\n"
)

BACKUP_SCRIPT = (
    "#!/bin/bash\n"
    "# /home/finapp/bin/nightly-backup.sh\n"
    "# Runs via /etc/cron.d/fin-backup at 02:00 UTC nightly.\n"
    "set -euo pipefail\n"
    "\n"
    "DEST=/var/backups/finance\n"
    "TS=$(date -u +%Y%m%dT%H%M%SZ)\n"
    "mkdir -p \"$DEST\"\n"
    "\n"
    "pg_dump -h localhost -U finapp_ro -Fc finance_prod \\\n"
    "  > \"$DEST/finance_prod-${TS}.pgdump\"\n"
    "\n"
    "find \"$DEST\" -name 'finance_prod-*.pgdump' -mtime +30 -delete\n"
)

CRON_FIN_BACKUP = (
    "# /etc/cron.d/fin-backup — managed by ops\n"
    "SHELL=/bin/bash\n"
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    "\n"
    "0 2 * * * finapp /home/finapp/bin/nightly-backup.sh >> /home/finapp/logs/backup.log 2>&1\n"
    "0 */4 * * * finapp /usr/bin/curl -s -o /dev/null https://fin-audit.prod.acmecorp.internal/heartbeat\n"
)

POSTGRES_CONF = (
    "# /etc/postgresql/14/main/postgresql.conf (extract)\n"
    "listen_addresses = 'localhost,10.20.4.11'\n"
    "port = 5432\n"
    "max_connections = 200\n"
    "shared_buffers = 2GB\n"
    "effective_cache_size = 6GB\n"
    "work_mem = 16MB\n"
    "maintenance_work_mem = 512MB\n"
    "wal_level = replica\n"
    "archive_mode = on\n"
    "archive_command = 'test ! -f /var/lib/postgresql/14/archive/%f && cp %p /var/lib/postgresql/14/archive/%f'\n"
    "log_destination = 'stderr'\n"
    "logging_collector = on\n"
    "log_directory = '/var/log/postgresql'\n"
    "log_filename = 'postgresql-%a.log'\n"
    "log_min_duration_statement = 250\n"
    "ssl = on\n"
    "ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'\n"
    "ssl_key_file  = '/etc/ssl/private/ssl-cert-snakeoil.key'\n"
)

PG_HBA = (
    "# /etc/postgresql/14/main/pg_hba.conf\n"
    "local   all             postgres                                peer\n"
    "local   all             all                                     peer\n"
    "host    finance_prod    finapp_rw       127.0.0.1/32            scram-sha-256\n"
    "host    finance_prod    finapp_ro       127.0.0.1/32            scram-sha-256\n"
    "host    finance_prod    finapp_ro       10.20.4.12/32           scram-sha-256\n"
    "host    replication     replicator      10.20.4.12/32           scram-sha-256\n"
    "host    all             all             0.0.0.0/0               reject\n"
)

AUTH_LOG_FIN = (
    "Apr 15 07:11:04 fin-db-prod-01 sshd[11203]: Accepted publickey for finapp from 10.20.4.4 port 51221\n"
    "Apr 15 07:11:04 fin-db-prod-01 sshd[11203]: pam_unix(sshd:session): session opened for user finapp by (uid=0)\n"
    "Apr 15 19:00:04 fin-db-prod-01 sudo:   finapp : TTY=pts/1 ; PWD=/home/finapp ; USER=root ; COMMAND=/bin/systemctl restart finapp.service\n"
    "Apr 16 02:00:04 fin-db-prod-01 CRON[28411]: pam_unix(cron:session): session opened for user finapp by (uid=0)\n"
    "Apr 16 02:01:12 fin-db-prod-01 CRON[28411]: pam_unix(cron:session): session closed for user finapp\n"
)

SYSLOG_FIN = (
    "Apr 16 02:00:04 fin-db-prod-01 CRON[28411]: (finapp) CMD (/home/finapp/bin/nightly-backup.sh)\n"
    "Apr 16 02:01:12 fin-db-prod-01 postgres[1844]: [1012-1] LOG:  checkpoint complete: wrote 4812 buffers (2.9%)\n"
    "Apr 16 04:00:00 fin-db-prod-01 systemd[1]: Starting Daily apt download activities...\n"
    "Apr 16 04:00:02 fin-db-prod-01 systemd[1]: apt-daily.service: Succeeded.\n"
    "Apr 16 08:00:00 fin-db-prod-01 finapp[2110]: health check OK\n"
)

BASH_HISTORY_ROOT = (
    "apt update\n"
    "apt upgrade -y\n"
    "reboot\n"
    "systemctl status postgresql\n"
    "systemctl status finapp\n"
    "tail -n 100 /var/log/syslog\n"
    "exit\n"
)

BASHRC_ROOT = (
    "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    "alias ll='ls -alF'\n"
)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def dir_entry(owner, group, perms, created, modified, children):
    return {
        "type": "directory",
        "owner": owner,
        "group": group,
        "permissions": perms,
        "created": created,
        "modified": modified,
        "children": sorted(children),
    }


def file_entry(owner, group, perms, created, modified, content):
    return {
        "type": "file",
        "owner": owner,
        "group": group,
        "permissions": perms,
        "created": created,
        "modified": modified,
        "size_bytes": len(content.encode("utf-8")),
        "content": content,
    }


# ---------------------------------------------------------------------------
# Persona
# ---------------------------------------------------------------------------

PERSONA = {
    "persona_id": "finance_server",
    "display_name": "Finance Production Server",
    "threat_trigger_level": "critical",
    "schema_version": 1,

    "system": {
        "hostname": "fin-db-prod-01",
        "os": "Ubuntu 20.04.6 LTS",
        "kernel": "5.4.0-150-generic",
        "arch": "x86_64",
        "uptime_seconds": UPTIME_SECONDS,
        "boot_time": LAST_BOOT,
        "timezone": "UTC",
        "locale": "en_US.UTF-8",
    },

    "network": {
        "interfaces": [
            {"name": "eth0", "ip": "10.20.4.11", "mac": "0a:1f:2b:3c:4d:5e",
             "netmask": "255.255.255.0", "broadcast": "10.20.4.255", "state": "UP",
             "rx_bytes": 8_441_220_988, "tx_bytes": 4_912_773_445},
            {"name": "lo", "ip": "127.0.0.1", "mac": "00:00:00:00:00:00",
             "netmask": "255.0.0.0", "broadcast": None, "state": "UP",
             "rx_bytes": 2_184_441, "tx_bytes": 2_184_441},
        ],
        "open_ports": [22, 5432, 8443],
        "active_connections": [
            {"proto": "tcp",  "local_addr": "0.0.0.0:22",       "foreign_addr": "0.0.0.0:*",      "state": "LISTEN",     "pid": 912,  "program": "sshd"},
            {"proto": "tcp6", "local_addr": ":::22",             "foreign_addr": ":::*",           "state": "LISTEN",     "pid": 912,  "program": "sshd"},
            {"proto": "tcp",  "local_addr": "10.20.4.11:5432",   "foreign_addr": "0.0.0.0:*",      "state": "LISTEN",     "pid": 1844, "program": "postgres"},
            {"proto": "tcp",  "local_addr": "127.0.0.1:5432",    "foreign_addr": "0.0.0.0:*",      "state": "LISTEN",     "pid": 1844, "program": "postgres"},
            {"proto": "tcp6", "local_addr": ":::8443",           "foreign_addr": ":::*",           "state": "LISTEN",     "pid": 2110, "program": "java"},
            {"proto": "tcp",  "local_addr": "10.20.4.11:5432",   "foreign_addr": "10.20.4.12:41882","state": "ESTABLISHED","pid": 1901, "program": "postgres"},
            {"proto": "tcp",  "local_addr": "10.20.4.11:45118",  "foreign_addr": "10.20.4.20:443",  "state": "ESTABLISHED","pid": 2110, "program": "java"},
        ],
    },

    "users": [
        {
            "username": "root", "uid": 0, "gid": 0,
            "home": "/root", "shell": "/bin/bash",
            "groups": ["root"], "password_hash": "!",
            "last_login": "2026-01-17T03:18:22Z",
            "last_login_from": "10.20.4.4",
        },
        {
            "username": "postgres", "uid": 107, "gid": 113,
            "home": "/var/lib/postgresql", "shell": "/bin/bash",
            "groups": ["postgres", "ssl-cert"], "password_hash": "!",
            "last_login": None,
            "last_login_from": None,
        },
        {
            "username": "finapp", "uid": 1002, "gid": 1002,
            "home": "/home/finapp", "shell": "/bin/bash",
            "groups": ["finapp", "sudo"],
            "password_hash": "$6$aB9cD2eF$hG7kL0mN3pQ5rS8tU1vW4xY6zA9bC2dE5fH8iJ0kL3mN6oP9qR",
            "last_login": "2026-04-15T07:11:04Z",
            "last_login_from": "10.20.4.4",
        },
    ],

    "processes": [
        {"pid": 1,    "ppid": 0,    "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.0, "vsz": 172312, "rss": 13280, "tty": "?", "stat": "Ss",  "start": "Jan17", "time": "1:42",   "command": "/sbin/init"},
        {"pid": 488,  "ppid": 1,    "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.3, "vsz":  98432, "rss":  7744, "tty": "?", "stat": "Ss",  "start": "Jan17", "time": "8:14",   "command": "/lib/systemd/systemd-journald"},
        {"pid": 912,  "ppid": 1,    "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.1, "vsz":  70112, "rss":  6244, "tty": "?", "stat": "Ss",  "start": "Jan17", "time": "0:04",   "command": "sshd: /usr/sbin/sshd -D"},
        {"pid": 940,  "ppid": 1,    "user": "root",     "cpu_percent": 0.0, "mem_percent": 0.0, "vsz":  26412, "rss":  1988, "tty": "?", "stat": "Ss",  "start": "Jan17", "time": "0:12",   "command": "/usr/sbin/cron -f"},
        {"pid": 1844, "ppid": 1,    "user": "postgres", "cpu_percent": 0.2, "mem_percent": 4.1, "vsz": 2234112, "rss":218422, "tty": "?", "stat": "Ss",  "start": "Jan17", "time": "82:41",  "command": "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main -c config_file=/etc/postgresql/14/main/postgresql.conf"},
        {"pid": 1890, "ppid": 1844, "user": "postgres", "cpu_percent": 0.0, "mem_percent": 0.4, "vsz": 2221020, "rss": 20128, "tty": "?", "stat": "Ss",  "start": "Jan17", "time": "14:02",  "command": "postgres: 14/main: checkpointer"},
        {"pid": 1891, "ppid": 1844, "user": "postgres", "cpu_percent": 0.0, "mem_percent": 0.3, "vsz": 2221020, "rss": 16380, "tty": "?", "stat": "Ss",  "start": "Jan17", "time": "11:18",  "command": "postgres: 14/main: background writer"},
        {"pid": 1892, "ppid": 1844, "user": "postgres", "cpu_percent": 0.0, "mem_percent": 0.2, "vsz": 2221020, "rss": 14844, "tty": "?", "stat": "Ss",  "start": "Jan17", "time":  "9:47",  "command": "postgres: 14/main: walwriter"},
        {"pid": 1893, "ppid": 1844, "user": "postgres", "cpu_percent": 0.0, "mem_percent": 0.3, "vsz": 2222180, "rss": 17112, "tty": "?", "stat": "Ss",  "start": "Jan17", "time":  "6:20",  "command": "postgres: 14/main: autovacuum launcher"},
        {"pid": 1901, "ppid": 1844, "user": "postgres", "cpu_percent": 0.1, "mem_percent": 0.5, "vsz": 2226488, "rss": 26112, "tty": "?", "stat": "Ss",  "start": "Jan17", "time": "22:41",  "command": "postgres: 14/main: walsender replicator 10.20.4.12(41882) streaming 3/A2E184C0"},
        {"pid": 2110, "ppid": 1,    "user": "finapp",   "cpu_percent": 0.9, "mem_percent": 9.2, "vsz": 6128442, "rss":489224, "tty": "?", "stat": "Ssl", "start": "Jan17", "time": "182:14", "command": "/usr/lib/jvm/java-17-openjdk-amd64/bin/java -Xms512m -Xmx2g -jar /home/finapp/finapp.jar --spring.profiles.active=prod"},
    ],

    "filesystem": {
        "/": dir_entry("root", "root", "755", INSTALL, LAST_UPDATE,
            ["bin","boot","dev","etc","home","lib","lib64","media","mnt",
             "opt","proc","root","run","sbin","srv","sys","tmp","usr","var"]),

        # /etc
        "/etc": dir_entry("root","root","755", INSTALL, LAST_UPDATE,
            ["cron.d","hostname","hosts","os-release","passwd","shadow","group",
             "postgresql","ssh"]),
        "/etc/hostname":   file_entry("root","root","644", INSTALL, INSTALL,     HOSTNAME_TXT),
        "/etc/hosts":      file_entry("root","root","644", INSTALL, LAST_UPDATE, HOSTS_TXT),
        "/etc/os-release": file_entry("root","root","644", INSTALL, INSTALL,     OS_RELEASE_TXT),
        "/etc/passwd":     file_entry("root","root","644", INSTALL, LAST_UPDATE, PASSWD_TXT),
        "/etc/shadow":     file_entry("root","shadow","640", INSTALL, LAST_UPDATE, SHADOW_TXT),
        "/etc/group":      file_entry("root","root","644", INSTALL, LAST_UPDATE, GROUP_TXT),

        "/etc/cron.d": dir_entry("root","root","755", INSTALL, LAST_UPDATE, ["fin-backup"]),
        "/etc/cron.d/fin-backup": file_entry("root","root","644", INSTALL, LAST_UPDATE, CRON_FIN_BACKUP),

        "/etc/postgresql":             dir_entry("root","root","755", INSTALL, LAST_UPDATE, ["14"]),
        "/etc/postgresql/14":          dir_entry("root","root","755", INSTALL, LAST_UPDATE, ["main"]),
        "/etc/postgresql/14/main":     dir_entry("postgres","postgres","755", INSTALL, LAST_UPDATE,
                                                 ["pg_hba.conf","postgresql.conf"]),
        "/etc/postgresql/14/main/postgresql.conf": file_entry("postgres","postgres","644", INSTALL, LAST_UPDATE, POSTGRES_CONF),
        "/etc/postgresql/14/main/pg_hba.conf":     file_entry("postgres","postgres","640", INSTALL, LAST_UPDATE, PG_HBA),

        # /home/finapp + subtree
        "/home": dir_entry("root","root","755", INSTALL, INSTALL, ["finapp"]),
        "/home/finapp": dir_entry("finapp","finapp","750", INSTALL, RECENT_LOG,
            [".bash_history",".bashrc",".profile","bin","config","logs","reports"]),
        "/home/finapp/.bash_history": file_entry("finapp","finapp","600", INSTALL, RECENT_LOG, BASH_HISTORY_FINAPP),
        "/home/finapp/.bashrc":       file_entry("finapp","finapp","644", INSTALL, INSTALL,     BASHRC_FINAPP),
        "/home/finapp/.profile":      file_entry("finapp","finapp","644", INSTALL, INSTALL,     PROFILE_FINAPP),

        "/home/finapp/bin":          dir_entry("finapp","finapp","755", INSTALL, INSTALL, ["nightly-backup.sh"]),
        "/home/finapp/bin/nightly-backup.sh": file_entry("finapp","finapp","750", INSTALL, INSTALL, BACKUP_SCRIPT),

        "/home/finapp/config":       dir_entry("finapp","finapp","750", INSTALL, LAST_UPDATE,
                                               ["application.yml","database.yml"]),
        "/home/finapp/config/database.yml":    file_entry("finapp","finapp","600", INSTALL, LAST_UPDATE, DATABASE_YML),
        "/home/finapp/config/application.yml": file_entry("finapp","finapp","600", INSTALL, LAST_UPDATE, APPLICATION_YML),

        "/home/finapp/logs":         dir_entry("finapp","finapp","750", INSTALL, RECENT_LOG,
                                               ["audit.log","finapp.log"]),
        "/home/finapp/logs/finapp.log": file_entry("finapp","finapp","640", "2026-04-01T00:00:00Z", NIGHTLY_BATCH, FINAPP_LOG),
        "/home/finapp/logs/audit.log":  file_entry("finapp","finapp","640", "2026-04-01T00:00:00Z", RECENT_LOG, AUDIT_LOG),

        "/home/finapp/reports":      dir_entry("finapp","finapp","750", INSTALL, Q1_REPORT,
                                               ["q1-2026-transactions.csv"]),
        "/home/finapp/reports/q1-2026-transactions.csv":
            file_entry("finapp","finapp","640", Q1_REPORT, Q1_REPORT, TRANSACTIONS_CSV),

        # /root
        "/root": dir_entry("root","root","700", INSTALL, LAST_UPDATE,
            [".bash_history",".bashrc"]),
        "/root/.bash_history": file_entry("root","root","600", INSTALL, LAST_UPDATE, BASH_HISTORY_ROOT),
        "/root/.bashrc":       file_entry("root","root","644", INSTALL, INSTALL,     BASHRC_ROOT),

        # /tmp
        "/tmp": dir_entry("root","root","1777", INSTALL, RECENT_LOG, []),

        # /var
        "/var": dir_entry("root","root","755", INSTALL, LAST_UPDATE,
            ["backups","lib","log","tmp"]),
        "/var/backups": dir_entry("root","root","755", INSTALL, NIGHTLY_BATCH, ["finance"]),
        "/var/backups/finance": dir_entry("finapp","finapp","750", INSTALL, NIGHTLY_BATCH, []),

        "/var/lib": dir_entry("root","root","755", INSTALL, LAST_UPDATE, ["postgresql"]),
        "/var/lib/postgresql": dir_entry("postgres","postgres","755", INSTALL, LAST_UPDATE, ["14"]),
        "/var/lib/postgresql/14": dir_entry("postgres","postgres","755", INSTALL, LAST_UPDATE, ["main"]),
        "/var/lib/postgresql/14/main": dir_entry("postgres","postgres","700", INSTALL, NIGHTLY_BATCH, []),

        "/var/log": dir_entry("root","root","755", INSTALL, RECENT_LOG,
            ["auth.log","postgresql","syslog"]),
        "/var/log/auth.log": file_entry("root","adm","640", "2026-04-01T00:00:00Z", RECENT_LOG, AUTH_LOG_FIN),
        "/var/log/syslog":   file_entry("syslog","adm","640", "2026-04-01T00:00:00Z", RECENT_LOG, SYSLOG_FIN),
        "/var/log/postgresql": dir_entry("postgres","postgres","755", INSTALL, RECENT_LOG, []),
    },

    "disk": {
        "total_gb": 500,
        "used_gb": 188.4,
        "available_gb": 286.2,
        "use_percent": 40,
        "filesystem": "/dev/mapper/vg0-root",
        "mount": "/",
    },

    "memory": {
        "total_mb": 16384,
        "used_mb": 9812,
        "free_mb": 1204,
        "shared_mb": 412,
        "buff_cache_mb": 5368,
        "available_mb": 5984,
    },

    "environment_defaults": {
        "finapp": {
            "USER": "finapp",
            "HOME": "/home/finapp",
            "SHELL": "/bin/bash",
            "PATH": "/usr/lib/jvm/java-17-openjdk-amd64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "PWD": "/home/finapp",
            "PS1": "finapp@fin-db-prod-01:~$ ",
            "JAVA_HOME": "/usr/lib/jvm/java-17-openjdk-amd64",
            "FINAPP_HOME": "/home/finapp",
            "FINAPP_ENV": "prod",
        },
        "postgres": {
            "USER": "postgres",
            "HOME": "/var/lib/postgresql",
            "SHELL": "/bin/bash",
            "PATH": "/usr/lib/postgresql/14/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "PWD": "/var/lib/postgresql",
            "PS1": "postgres@fin-db-prod-01:~$ ",
            "PGDATA": "/var/lib/postgresql/14/main",
        },
        "root": {
            "USER": "root",
            "HOME": "/root",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "PWD": "/root",
            "PS1": "root@fin-db-prod-01:~# ",
        },
    },
}


def main() -> int:
    out = Path(__file__).resolve().parent.parent / "personas" / "finance_server.json"
    now = datetime(2026, 4, 16, 12, 0, 0, tzinfo=timezone.utc)

    errors = validate(PERSONA, now)
    if errors:
        print("CONSISTENCY VIOLATIONS:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    out.write_text(json.dumps(PERSONA, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes, 0 consistency violations)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
