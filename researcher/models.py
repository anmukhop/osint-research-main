import uuid
from django.db import models
import secrets
import string
from django.contrib.auth import get_user_model

User = get_user_model()


class Session(models.Model):
    """Anonymous user session, identified by a UUID cookie."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=['last_seen_at'])]

    def __str__(self):
        return f"Session({self.id})"


class Query(models.Model):
    """One row per user query submitted via the search UI."""
    id = models.BigAutoField(primary_key=True)
    session = models.ForeignKey(
        Session, on_delete=models.CASCADE, related_name='queries'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='queries',
    )
    team = models.ForeignKey(
        'Team',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='queries',
    )

    user_query = models.TextField()
    interpreted_action = models.CharField(max_length=128, null=True, blank=True)
    interpreted_params = models.JSONField(null=True, blank=True)
    server_used = models.CharField(max_length=64, null=True, blank=True)

    success = models.BooleanField(default=False)
    error = models.TextField(null=True, blank=True)
    summary = models.TextField(null=True, blank=True)
    raw_results = models.JSONField(null=True, blank=True)

    duration_ms = models.IntegerField(null=True, blank=True)

    suggested_queries = models.JSONField(null=True, blank=True)
    parent_query = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='child_queries',
    )

    class Meta:
        indexes = [
            models.Index(fields=['session', '-created_at']),
            models.Index(fields=['team', '-created_at']),
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['-created_at']),
            models.Index(fields=['interpreted_action']),
            models.Index(fields=['parent_query']),
        ]

    def __str__(self):
        return f"Query({self.id}: {self.user_query[:50]})"


class ToolCall(models.Model):
    """One row per individual tool invocation within a query.

    Currently each Query produces exactly one ToolCall. Once we add
    multi-tool orchestration in step 2, a single Query may produce many.
    """
    id = models.BigAutoField(primary_key=True)
    query = models.ForeignKey(
        Query, on_delete=models.CASCADE, related_name='tool_calls'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    tool_name = models.CharField(max_length=128)
    server_name = models.CharField(max_length=64)
    arguments = models.JSONField(null=True, blank=True)
    result = models.JSONField(null=True, blank=True)

    success = models.BooleanField(default=False)
    error = models.TextField(null=True, blank=True)
    duration_ms = models.IntegerField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['query', 'created_at']),
            models.Index(fields=['tool_name']),
        ]

    def __str__(self):
        return f"ToolCall({self.tool_name})"
    
def _generate_invite_code() -> str:
    """Generate a short, human-friendly invite code.

    Uses uppercase A–Z and digits 0–9 minus visually ambiguous chars (O/0, I/1).
    10 characters gives ~10^15 possibilities — collision risk is effectively nil
    for our scale, but we still check for uniqueness at save time.
    """
    alphabet = "".join(c for c in string.ascii_uppercase + string.digits if c not in "O0I1")
    return "".join(secrets.choice(alphabet) for _ in range(10))


class Team(models.Model):
    """A collaborative workspace. Users join via invite code and share queries.

    For the MVP, teams are additive only — no leave / no delete / no rename.
    Each team has a unique invite code; the owner is the user who created it.
    """
    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=120)
    invite_code = models.CharField(max_length=12, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='teams_created',
    )
    members = models.ManyToManyField(
        User,
        through='TeamMembership',
        related_name='teams',
    )

    class Meta:
        indexes = [models.Index(fields=['-created_at'])]

    def save(self, *args, **kwargs):
        """Assign a unique invite_code on first save if one isn't set."""
        if not self.invite_code:
            for _ in range(5):
                code = _generate_invite_code()
                if not Team.objects.filter(invite_code=code).exists():
                    self.invite_code = code
                    break
            else:
                # Vanishingly unlikely. Bail loudly rather than silently save bad data.
                raise RuntimeError("Could not generate a unique invite code after 5 tries")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Team({self.name}, {self.invite_code})"


class TeamMembership(models.Model):
    """Through-table for the User<->Team M2M with join metadata and role."""
    ROLE_OWNER = "owner"
    ROLE_MEMBER = "member"
    ROLE_CHOICES = [
        (ROLE_OWNER, "Owner"),
        (ROLE_MEMBER, "Member"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='memberships')
    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name='memberships')
    joined_at = models.DateTimeField(auto_now_add=True)
    last_active_at = models.DateTimeField(null=True, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_MEMBER)

    class Meta:
        unique_together = [('user', 'team')]
        indexes = [
            models.Index(fields=['user', 'team']),
            models.Index(fields=['team', 'role']),
        ]

    def __str__(self):
        return f"TeamMembership({self.user} in {self.team}, {self.role})"


class BrowsingEvent(models.Model):
    """Browsing event captured by the browser extension for context-aware research."""
    EVENT_VISIT = 'visit'
    EVENT_SEARCH = 'search'
    EVENT_TYPES = [
        (EVENT_VISIT, 'Visit'),
        (EVENT_SEARCH, 'Search'),
    ]

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='browsing_events')
    team = models.ForeignKey(
        'Team', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='browsing_events',
    )
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES, default=EVENT_VISIT)
    url = models.TextField()
    site_name = models.CharField(max_length=255)
    page_title = models.CharField(max_length=500, blank=True)
    top_heading = models.CharField(max_length=500, blank=True)
    search_query = models.CharField(max_length=1000, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', '-created_at'], name='browsing_user_created_idx'),
            models.Index(fields=['team', '-created_at'], name='browsing_team_created_idx'),
        ]

    def __str__(self):
        return f"BrowsingEvent({self.event_type}: {self.site_name})"


class Notification(models.Model):
    """In-app notification for team members when a teammate runs a query,
    or when the AI generates a browsing-context research suggestion.

    For query notifications: query is set, suggestion_text is blank.
    For suggestion notifications: query is None, suggestion_text carries the content.
    """
    id = models.BigAutoField(primary_key=True)
    recipient = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='notifications',
    )
    query = models.ForeignKey(
        Query,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='notifications',
    )
    suggestion_text = models.TextField(blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['recipient', 'is_read', '-created_at']),
        ]

    def __str__(self):
        return f"Notification(to={self.recipient_id}, query={self.query_id}, read={self.is_read})"


class BrowsingTeamSummary(models.Model):
    """Cached Claude Haiku analysis of team browsing activity.

    One row per team. Regenerated when stale (>30 min) and browsing
    events are present. The data JSON holds the full structured summary
    plus generated OSINT query suggestions.
    """
    team = models.OneToOneField(
        Team,
        on_delete=models.CASCADE,
        related_name='browsing_summary',
        primary_key=True,
    )
    data = models.JSONField(default=dict)
    generated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"BrowsingTeamSummary(team={self.team_id})"