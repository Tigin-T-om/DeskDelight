from django.contrib import admin
from .models import Product, CustomUser

# Custom admin interface for Product
class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'price', 'quantity_available', 'description')
    search_fields = ('name', 'category')
    list_filter = ('category',)
    ordering = ('name',)

# Register Product model with custom admin interface
admin.site.register(Product, ProductAdmin)

# Register CustomUser model (optional customization)
admin.site.register(CustomUser)

from django.contrib import admin
from .models import Order, OrderItem

# Define a custom admin class for OrderItem
class OrderItemInline(admin.TabularInline):
    model = OrderItem
    extra = 1  # The number of empty forms to display for adding new order items

# Define a custom admin class for Order
class OrderAdmin(admin.ModelAdmin):
    list_display = ('id', 'customer', 'total_price', 'status', 'created_at', 'estimated_delivery_date')
    list_filter = ('status', 'created_at')
    search_fields = ('customer__username', 'status', 'created_at')
    inlines = [OrderItemInline]  # Add the inline for OrderItem

# Register the models with the admin interface
admin.site.register(Order, OrderAdmin)
admin.site.register(OrderItem)