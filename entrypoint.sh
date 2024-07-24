#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# if [ -z "$CONFIG" ]; then
#   echo "Container failed to start, missing CONFIG environment variable."
#   exit 1
# fi

# set certain environment variables if DEVELOPMENT is set to true
if [ "$DEVELOPMENT" = "true" ]; then
    export OAUTHLIB_INSECURE_TRANSPORT=1
fi

echo "Running migrations..."
poetry run migrate

echo "Starting server..."
gunicorn -w 1 --bind :8080 getwvkeys.main:app
exec "$@"