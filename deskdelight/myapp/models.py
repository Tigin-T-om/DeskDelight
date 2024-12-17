from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils.timezone import now
from datetime import timedelta

# Custom user model
class CustomUser(AbstractUser):
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)

class Product(models.Model):
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
    quantity_available = models.PositiveIntegerField(default=0)  # Track available stock

    def __str__(self):
        return f'{self.name} ({self.get_category_display()})'

class Cart(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    status = models.CharField(
        max_length=10,
        choices=[('active', 'Active'), ('ordered', 'Ordered')],
        default='active'
    )

    def __str__(self):
        return f'{self.user.username} - {self.product.name} - {self.quantity}'

def default_delivery_date():
    return timezone.now().date() + timedelta(days=5)

class Order(models.Model):
    customer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(
        max_length=20, 
        choices=[
            ('Pending', 'Pending'),
            ('Shipped', 'Shipped'),
            ('Delivered', 'Delivered'),
            ('Cancelled', 'Cancelled')
        ],
        default='Pending',
    )
    shipping_address = models.TextField()
    phone_number = models.CharField(max_length=15)
    created_at = models.DateTimeField(auto_now_add=True)
    estimated_delivery_date = models.DateField(default=default_delivery_date)  # Use callable

    def __str__(self):
        return f"Order {self.id} - {self.status}"

class OrderItem(models.Model):
    order = models.ForeignKey(Order, related_name='orderitem_set', on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    total_price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f"Item {self.id} - {self.product.name} x {self.quantity}"
