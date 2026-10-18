import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('researcher', '0005_notification'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='BrowsingEvent',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('event_type', models.CharField(
                    choices=[('visit', 'Visit'), ('search', 'Search')],
                    default='visit',
                    max_length=20,
                )),
                ('url', models.TextField()),
                ('site_name', models.CharField(max_length=255)),
                ('page_title', models.CharField(blank=True, max_length=500)),
                ('top_heading', models.CharField(blank=True, max_length=500)),
                ('search_query', models.CharField(blank=True, max_length=1000)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='browsing_events',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('team', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='browsing_events',
                    to='researcher.team',
                )),
            ],
            options={
                'indexes': [
                    models.Index(fields=['user', '-created_at'], name='browsing_user_created_idx'),
                    models.Index(fields=['team', '-created_at'], name='browsing_team_created_idx'),
                ],
            },
        ),
    ]
