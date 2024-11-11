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
