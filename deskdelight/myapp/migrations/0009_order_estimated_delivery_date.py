# Generated by Django 5.1.2 on 2024-11-16 11:35

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0008_remove_order_product_remove_order_quantity_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='order',
            name='estimated_delivery_date',
            field=models.DateField(default=datetime.datetime(2024, 11, 21, 11, 35, 6, 648611, tzinfo=datetime.timezone.utc)),
        ),
    ]
