from django.contrib import admin
from .models import Product
from .models import CustomUser

admin.site.register(Product)
admin.site.register(CustomUser)