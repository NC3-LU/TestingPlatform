# Generated by Django 3.2.8 on 2021-10-19 12:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('testing', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='TlsScanHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scan_id', models.IntegerField()),
                ('domain', models.CharField(max_length=255, unique=True)),
            ],
        ),
    ]
