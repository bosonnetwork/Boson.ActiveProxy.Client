#!/bin/bash
#
# Launcher for the Boson Active Proxy client.
#
# Expects the distribution layout:
#
#   <base>/bin/active-proxy.sh   this script
#   <base>/lib/*.jar             the client and its dependencies
#   <base>/jre/                  bundled JRE (optional)
#
# Arguments are passed straight through, so `active-proxy.sh --help` lists the
# options and exit codes. With no arguments the client reads
# $HOME/.config/boson/client/active-proxy.yaml.
#
# Set JAVA_OPTS to pass extra options to the JVM.

# Determine the script directory
PRG="$0"
while [ -h "$PRG" ] ; do
  ls=`ls -ld "$PRG"`
  link=`expr "$ls" : '.*-> \(.*\)$'`
  if expr "$link" : '/.*' > /dev/null; then
    PRG="$link"
  else
    PRG=`dirname "$PRG"`/"$link"
  fi
done
PRGDIR=`dirname "$PRG"`
BASEDIR=`cd "$PRGDIR/.." >/dev/null; pwd`

# Prefer the bundled JRE, but stay usable outside the full distribution
if [ -x "$BASEDIR/jre/bin/java" ]; then
  JAVA_EXEC="$BASEDIR/jre/bin/java"
elif [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JAVA_EXEC="$JAVA_HOME/bin/java"
elif command -v java >/dev/null 2>&1; then
  JAVA_EXEC="java"
else
  echo "Error: no Java runtime found." >&2
  echo "Looked for a bundled JRE at $BASEDIR/jre, then \$JAVA_HOME, then java on the PATH." >&2
  exit 1
fi

LIB_DIR="$BASEDIR/lib"
if [ ! -d "$LIB_DIR" ]; then
  echo "Error: library directory not found at $LIB_DIR" >&2
  echo "This script expects to live in <base>/bin alongside <base>/lib." >&2
  exit 1
fi

# Define standard log path
LOG_DIR="$HOME/.cache/boson/client/logs"

# Ensure the log directory exists
mkdir -p "$LOG_DIR"

# Point logback at the shared configuration only when it is actually installed,
# otherwise logback reports the missing file before falling back to its default
JVM_OPTS=(-Dlogback.statusListenerClass=ch.qos.logback.core.status.NopStatusListener -DLOG_DIR="$LOG_DIR")
if [ -f "$HOME/.config/boson/logback.xml" ]; then
  JVM_OPTS+=(-Dlogback.configurationFile="$HOME/.config/boson/logback.xml")
fi

# Run the Active Proxy client. exec keeps this shell out of the way so that
# SIGTERM/SIGINT reach the JVM directly and its shutdown hook can close the
# tunnel and release the single-instance lock.
# JAVA_OPTS is deliberately unquoted so that it splits into separate arguments.
exec "$JAVA_EXEC" \
  "${JVM_OPTS[@]}" \
  ${JAVA_OPTS:-} \
  -cp "$LIB_DIR/*" \
  io.bosonnetwork.activeproxy.Launcher \
  "$@"
