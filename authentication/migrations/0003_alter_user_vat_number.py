# Generated by Django 3.2.8 on 2021-11-01 09:42
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0002_auto_20211028_0851"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="vat_number",
            field=models.CharField(default=None, max_length=200),
            preserve_default=False,
        ),
    ]
