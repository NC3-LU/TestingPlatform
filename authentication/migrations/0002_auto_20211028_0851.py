# Generated by Django 3.2.8 on 2021-10-28 08:51
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("authentication", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="subscription",
            name="tier_level",
            field=models.PositiveSmallIntegerField(
                choices=[(1, "PRO"), (2, "BUSINESS")], help_text="Choose a package"
            ),
        ),
        migrations.AlterField(
            model_name="subscriptionrequest",
            name="tier_level",
            field=models.PositiveSmallIntegerField(
                choices=[(1, "PRO"), (2, "BUSINESS")], help_text="Choose a package"
            ),
        ),
    ]
