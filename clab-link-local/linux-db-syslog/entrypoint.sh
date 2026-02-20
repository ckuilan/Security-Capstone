
set -e

mkdir -p /run/sshd
mkdir -p /var/log/couchdb
mkdir -p /data/storage



dhclient eth1 2>/dev/null || true




mkdir -p /run/sshd
/usr/sbin/sshd -D &
SSH_PID=$!




/usr/sbin/rsyslogd -n &
RSYSLOG_PID=$!



/opt/couchdb/bin/couchdb > /tmp/couchdb.log 2>&1 &
COUCHDB_PID=$!
sleep 5



curl -s -X PUT http://admin:password123@localhost:5984/pa-logs >/dev/null 2>&1 || true



(while true; do
  tail -n 100 /var/log/syslog 2>/dev/null | grep "PA-VM" 2>/dev/null | python3 /opt/ingest-logs.py 2>/dev/null
  sleep 120
done) &
INGESTOR_PID=$!



while true; do
  if ! kill -0 $SSH_PID 2>/dev/null; then
    /usr/sbin/sshd -D &
    SSH_PID=$!
  fi
  if ! kill -0 $RSYSLOG_PID 2>/dev/null; then
    /usr/sbin/rsyslogd -n &
    RSYSLOG_PID=$!
  fi
  if ! kill -0 $COUCHDB_PID 2>/dev/null; then
    /opt/couchdb/bin/couchdb > /tmp/couchdb.log 2>&1 &
    COUCHDB_PID=$!
  fi
  if ! kill -0 $INGESTOR_PID 2>/dev/null; then
    (while true; do
      tail -n 100 /var/log/syslog 2>/dev/null | grep "PA-VM" 2>/dev/null | python3 /opt/ingest-logs.py 2>/dev/null
      sleep 120
    done) &
    INGESTOR_PID=$!
  fi
  sleep 30
done
