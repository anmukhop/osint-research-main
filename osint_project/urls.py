"""
URL configuration for OSINT Research Platform - MVP3

Endpoints:
- GET  /                       - Main page with search UI
- POST /parse/                 - Parse query for confirmation
- POST /search/                - Execute search (legacy, non-streaming)
- GET  /search/stream/         - Execute search with SSE progress streaming
- GET  /capabilities/          - Get available tools info

- GET  /accounts/login/        - Login form (Django built-in)
- POST /accounts/login/        - Submit login
- POST /accounts/logout/       - Logout (Django built-in)
- GET  /accounts/signup/       - Signup form
- POST /accounts/signup/       - Create account
- GET  /accounts/password_*/   - Password reset flow (Django built-in, unused for now)
"""
from django.contrib import admin
from django.urls import path, include
from researcher import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('parse/', views.parse_query, name='parse_query'),
    path('search/stream/', views.search_stream, name='search_stream'),
    path('thread/<int:parent_id>/', views.thread_history, name='thread_history'),
    path('capabilities/', views.capabilities, name='capabilities'),
    path('benchmark/', views.benchmark, name='benchmark'),
    path('benchmark/run/', views.benchmark_run, name='benchmark_run'),

    # Auth: signup is ours, everything else (login/logout/password reset)
    # is Django's built-in set under /accounts/.
    path('accounts/signup/', views.signup, name='signup'),
    path('accounts/', include('django.contrib.auth.urls')),

    # Teams: create, join, switch, list.
    path('teams/', views.teams_list, name='teams_list'),
    path('teams/new/', views.team_create, name='team_create'),
    path('teams/join/', views.team_join, name='team_join'),
    path('teams/<int:team_id>/switch/', views.team_switch, name='team_switch'),
    path('workspace/', views.workspace, name='workspace'),
    path('workspace/refresh-context/', views.workspace_refresh_context, name='workspace_refresh_context'),
    path('workspace/context-simulation/', views.workspace_context_simulation, name='workspace_context_simulation'),
    path('workspace/q/<int:query_id>/', views.workspace_query_detail, name='workspace_query_detail'),
    path('notifications/', views.notifications_list, name='notifications_list'),
    path('notifications/<int:notif_id>/read/', views.notification_mark_read, name='notification_mark_read'),

    # Browser extension API — CSRF exempt, session-cookie authenticated
    path('api/extension/status/', views.extension_status, name='extension_status'),
    path('api/extension/toggle/', views.extension_toggle, name='extension_toggle'),
    path('api/extension/events/', views.extension_events_create, name='extension_events_create'),
    path('api/extension/events/recent/', views.extension_events_list, name='extension_events_list'),
]
