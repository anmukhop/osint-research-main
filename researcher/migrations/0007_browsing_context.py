import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('researcher', '0006_browsingevent'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # 1. Make Notification.query nullable (was CASCADE NOT NULL → SET_NULL nullable)
        migrations.AlterField(
            model_name='notification',
            name='query',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='notifications',
                to='researcher.query',
            ),
        ),

        # 2. Add suggestion_text to Notification
        migrations.AddField(
            model_name='notification',
            name='suggestion_text',
            field=models.TextField(blank=True, default=''),
            preserve_default=False,
        ),

        # 3. Create BrowsingTeamSummary
        migrations.CreateModel(
            name='BrowsingTeamSummary',
            fields=[
                ('team', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    primary_key=True,
                    related_name='browsing_summary',
                    serialize=False,
                    to='researcher.team',
                )),
                ('data', models.JSONField(default=dict)),
                ('generated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
