# Generated by Django 2.2.17 on 2021-03-23 16:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("authorizations", "0011_auto_20191114_0728"),
    ]

    operations = [
        migrations.AlterField(
            model_name="authorizationsconfig",
            name="component",
            field=models.CharField(
                choices=[
                    ("ac", "Autorisaties API"),
                    ("nrc", "Notificaties API"),
                    ("zrc", "Zaken API"),
                    ("ztc", "Catalogi API"),
                    ("drc", "Documenten API"),
                    ("brc", "Besluiten API"),
                ],
                default="zrc",
                max_length=50,
                verbose_name="component",
            ),
        ),
        migrations.AlterField(
            model_name="autorisatie",
            name="component",
            field=models.CharField(
                choices=[
                    ("ac", "Autorisaties API"),
                    ("nrc", "Notificaties API"),
                    ("zrc", "Zaken API"),
                    ("ztc", "Catalogi API"),
                    ("drc", "Documenten API"),
                    ("brc", "Besluiten API"),
                ],
                help_text="Component waarop autorisatie van toepassing is.",
                max_length=50,
                verbose_name="component",
            ),
        ),
    ]