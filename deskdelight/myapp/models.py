from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.
class CustomUser(AbstractUser):
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)

class Product(models.Model):
    # Define the choices for categories
    CATEGORY_CHOICES = [
        ('chair', 'Chair'),
        ('table', 'Table'),
    ]

    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='products/', default='products/default.jpg')
    category = models.CharField(
        max_length=50,
        choices=CATEGORY_CHOICES,
        default='chair'
    )

    def __str__(self):
        return f'{self.name} ({self.get_category_display()})'