# Generated by Django 4.1.3 on 2022-12-14 17:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_user_branch_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='ordersdelivery',
            name='trip_count',
            field=models.IntegerField(default=0),
        ),
    ]
