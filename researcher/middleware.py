import uuid

from django.conf import settings
from django.http import Http404
from .models import Session

COOKIE_NAME = "osint_session_id"
COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year


class AnonymousSessionMiddleware:
    """Attaches an anonymous Session to every request.

    Reads a UUID from the `osint_session_id` cookie. If absent or invalid,
    creates a new Session and sets the cookie on the response.

    Access via `request.osint_session` in views.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        session = None
        new_session = False

        raw_id = request.COOKIES.get(COOKIE_NAME)
        if raw_id:
            try:
                session_id = uuid.UUID(raw_id)
                session = Session.objects.filter(id=session_id).first()
            except (ValueError, TypeError):
                pass

        if session is None:
            session = Session.objects.create()
            new_session = True
        else:
            # Touch last_seen_at without a full save
            Session.objects.filter(id=session.id).update()

        request.osint_session = session

        response = self.get_response(request)

        if new_session:
            response.set_cookie(
                COOKIE_NAME,
                str(session.id),
                max_age=COOKIE_MAX_AGE,
                httponly=True,
                samesite="Lax",
            )

        return response

class AdminLocalOnlyMiddleware:
    """With ADMIN_LOCAL_ONLY on, /admin/ is a 404 unless opened via localhost.

    Through an ngrok tunnel the Host header is the public ngrok name, so
    strangers with the link can't reach the admin login page.
    """

    LOCAL_HOSTS = {"localhost", "127.0.0.1"}

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.ADMIN_LOCAL_ONLY and request.path.startswith("/admin"):
            host = request.get_host().rsplit(":", 1)[0]
            if host not in self.LOCAL_HOSTS:
                raise Http404()
        return self.get_response(request)
