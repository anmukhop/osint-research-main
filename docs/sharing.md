# Sharing your local server (ngrok)

**How it works:** the `ngrok` program on your laptop opens an outgoing connection (a tunnel) to ngrok's servers. Visits to your public link (`https://<name>.ngrok-free.dev`, same every time) come down that tunnel to `localhost:8000`. To the app, everyone looks like they're on your laptop, so the app decides who gets in. All AI calls go out from your laptop, so it must be on the VT VPN; visitors don't need it.

**One-time setup**
1. `brew install ngrok`, make a free ngrok.com account, then `ngrok config add-authtoken <token>`.
2. In `.env`: `DJANGO_SECRET_KEY=<python3.11 -c 'from django.core.management.utils import get_random_secret_key as g; print(g())'>` and `SIGNUP_CODE=<any phrase>`. The script won't start without both.
3. Make yourself an admin: `python manage.py createsuperuser`.

**Each session**
1. Stop your normal server, run `scripts/share_with_ngrok.sh`, and give people the printed link plus the sign-up code. Ctrl+C stops sharing.
2. They click **Visit Site** on ngrok's warning page, sign up with the code, and join your team with its invite code.

**What's locked while sharing**
- Sign-up needs `SIGNUP_CODE`. Change it in `.env` and restart if it leaks.
- `/admin/` is "Not Found" on the link; use `http://localhost:8000/admin/`.
- Each account gets `DAILY_QUERY_CAP` searches per 24 hours (default 100; admins exempt). `/benchmark/` is admin-only.
- Only run the tunnel while a session needs it.

**Watch it:** `http://localhost:4040` shows every request through the tunnel; `server.log` shows the app's side. Free plan: 20k requests and 1 GB a month (a 1-hour, 3-person session is about 1,000 requests). The browser extension still points to `localhost`, so it only works on your laptop.
