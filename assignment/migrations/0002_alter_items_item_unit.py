# Generated by Django 4.1.3 on 2023-01-11 14:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('assignment', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='items',
            name='item_unit',
            field=models.CharField(max_length=50),
        ),
    ]