#!/usr/bin/env bash
# Share the local app with teammates through an ngrok tunnel.
#
# Runs the Django server on port 8000 in "shared" mode (DEBUG off, ngrok host
# allowed) and opens an ngrok tunnel to it. Ctrl+C stops both.
#
# One-time setup: install ngrok (brew install ngrok) and run
#   ngrok config add-authtoken <your token>
#
# usage: scripts/share_with_ngrok.sh
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3.11}"
PORT=8000

# The default SECRET_KEY in settings.py is public, so anyone could forge a
# login cookie. Refuse to share without a real one.
if [ -z "${DJANGO_SECRET_KEY:-}" ] && ! grep -q '^DJANGO_SECRET_KEY=.' .env 2>/dev/null; then
    echo "Set DJANGO_SECRET_KEY in .env before sharing. Generate one with:"
    echo "  $PYTHON -c 'from django.core.management.utils import get_random_secret_key as g; print(g())'"
    exit 1
fi

if lsof -ti "tcp:$PORT" -sTCP:LISTEN >/dev/null; then
    echo "Port $PORT is already in use. Stop that server first:"
    echo "  lsof -ti tcp:$PORT -sTCP:LISTEN | xargs kill"
    exit 1
fi

# Start ngrok first so we know the public URL before Django starts.
ngrok http "$PORT" --log=stdout > ngrok.log 2>&1 &
NGROK_PID=$!
trap 'kill $NGROK_PID ${DJANGO_PID:-} 2>/dev/null' EXIT

URL=""
for _ in $(seq 1 20); do
    URL=$(curl -s http://127.0.0.1:4040/api/tunnels \
        | "$PYTHON" -c "import json,sys; t=json.load(sys.stdin)['tunnels']; print(t[0]['public_url'] if t else '')" 2>/dev/null || true)
    [ -n "$URL" ] && break
    sleep 1
done
if [ -z "$URL" ]; then
    echo "ngrok did not start. See ngrok.log (is the authtoken set up?)"
    exit 1
fi
HOST="${URL#https://}"

# These override .env for this run only (python-dotenv doesn't overwrite
# variables that are already set).
export DEBUG=False
export REQUIRE_LOGIN=True
export ALLOWED_HOSTS="localhost,127.0.0.1,$HOST"
export CSRF_TRUSTED_ORIGINS="http://localhost:$PORT,http://127.0.0.1:$PORT,$URL"

# DEBUG=False serves static files from staticfiles/ via WhiteNoise.
"$PYTHON" manage.py collectstatic --noinput >/dev/null

"$PYTHON" manage.py runserver "$PORT" > server.log 2>&1 &
DJANGO_PID=$!

echo
echo "Sharing at: $URL"
echo "Teammates open that link, sign up, and join your team with its invite code."
echo "You can still use http://localhost:$PORT yourself."
echo "Server output: server.log   Tunnel output: ngrok.log"
echo "Press Ctrl+C to stop sharing."
wait $DJANGO_PID
