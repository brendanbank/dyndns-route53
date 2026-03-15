#!/bin/sh
set -e

# Fix ownership of instance directory (volume may have root-owned files
# from before the non-root user was introduced)
chown -R app:app /app/instance

exec setpriv --reuid=app --regid=app --init-groups "$@"
