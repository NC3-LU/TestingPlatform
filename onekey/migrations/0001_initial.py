# Generated by Django 4.2.3 on 2023-10-05 07:58

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

import onekey.models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="FirmwareAnalysisRequest",
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
                ("request_nb", models.CharField(max_length=12)),
                ("firmware_name", models.CharField(max_length=200)),
                ("firmware_vendor_name", models.CharField(max_length=200)),
                ("firmware_product_name", models.CharField(max_length=200)),
                (
                    "firmware_file",
                    models.FileField(upload_to=onekey.models.get_upload_path),
                ),
                (
                    "firmware_uuid",
                    models.UUIDField(blank=True, default=None, null=True),
                ),
                ("status", models.BooleanField(blank=True, default=None, null=True)),
                ("report_uuid", models.UUIDField(blank=True, default=None, null=True)),
                ("report_link", models.URLField(blank=True, default=None, null=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
