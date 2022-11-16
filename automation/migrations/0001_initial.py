# Generated by Django 3.2.8 on 2021-10-18 10:10

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("django_q", "0014_schedule_cluster"),
        ("testing", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="PingAutomatedTest",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "frequency",
                    models.CharField(
                        choices=[("D", "Dayly"), ("W", "Weekly"), ("M", "Monthly")],
                        help_text="Choose frequency of tests",
                        max_length=20,
                    ),
                ),
                (
                    "time",
                    models.TimeField(
                        default=django.utils.timezone.now,
                        help_text="Choose time for test execution",
                    ),
                ),
                (
                    "weekday",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("mo", "Monday"),
                            ("tu", "Tuesday"),
                            ("we", "Wednesday"),
                            ("th", "Thursday"),
                            ("fr", "Friday"),
                            ("sa", "Saturday"),
                            ("su", "Sunday"),
                        ],
                        help_text="If weekly, choose day of test",
                        max_length=15,
                        null=True,
                    ),
                ),
                (
                    "monthly_test_date",
                    models.IntegerField(
                        blank=True,
                        choices=[
                            (1, 1),
                            (2, 2),
                            (3, 3),
                            (4, 4),
                            (5, 5),
                            (6, 6),
                            (7, 7),
                            (8, 8),
                            (9, 9),
                            (10, 10),
                            (11, 11),
                            (12, 12),
                            (13, 13),
                            (14, 14),
                            (15, 15),
                            (16, 16),
                            (17, 17),
                            (18, 18),
                            (19, 19),
                            (20, 20),
                            (21, 21),
                            (22, 22),
                            (23, 23),
                            (24, 24),
                            (25, 25),
                            (26, 26),
                            (27, 27),
                            (28, 28),
                        ],
                        help_text="If monthly, select day in month up to the 28th",
                        null=True,
                    ),
                ),
                (
                    "schedule",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="django_q.schedule",
                    ),
                ),
                (
                    "target",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="testing.userdomain",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="HttpAutomatedTest",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "frequency",
                    models.CharField(
                        choices=[("D", "Dayly"), ("W", "Weekly"), ("M", "Monthly")],
                        help_text="Choose frequency of tests",
                        max_length=20,
                    ),
                ),
                (
                    "time",
                    models.TimeField(
                        default=django.utils.timezone.now,
                        help_text="Choose time for test execution",
                    ),
                ),
                (
                    "weekday",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("mo", "Monday"),
                            ("tu", "Tuesday"),
                            ("we", "Wednesday"),
                            ("th", "Thursday"),
                            ("fr", "Friday"),
                            ("sa", "Saturday"),
                            ("su", "Sunday"),
                        ],
                        help_text="If weekly, choose day of test",
                        max_length=15,
                        null=True,
                    ),
                ),
                (
                    "monthly_test_date",
                    models.IntegerField(
                        blank=True,
                        choices=[
                            (1, 1),
                            (2, 2),
                            (3, 3),
                            (4, 4),
                            (5, 5),
                            (6, 6),
                            (7, 7),
                            (8, 8),
                            (9, 9),
                            (10, 10),
                            (11, 11),
                            (12, 12),
                            (13, 13),
                            (14, 14),
                            (15, 15),
                            (16, 16),
                            (17, 17),
                            (18, 18),
                            (19, 19),
                            (20, 20),
                            (21, 21),
                            (22, 22),
                            (23, 23),
                            (24, 24),
                            (25, 25),
                            (26, 26),
                            (27, 27),
                            (28, 28),
                        ],
                        help_text="If monthly, select day in month up to the 28th",
                        null=True,
                    ),
                ),
                (
                    "schedule",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="django_q.schedule",
                    ),
                ),
                (
                    "target",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="testing.userdomain",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
    ]
