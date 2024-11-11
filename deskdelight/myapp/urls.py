from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name="index"),
    path('register_page', views.register_page, name="register_page"),
    path('register', views.register, name="register"),
    path('login_page', views.login_page, name="login_page"),
    path('login_view', views.login_view, name="login_view"),
    path('cart_page', views.cart_page, name="cart_page"),
    path('product_page', views.product_page, name='product_page'),
    path('product/<int:product_id>/', views.product_detail, name='product_detail'),  # Product detail view
    path('isLoggedIn', views.isLoggedIn, name='isLoggedIn'),
    path('logout/', views.logout_view, name='logout_view'),
    path('adminPage/', views.adminPage, name='adminPage'),  
    path('contact_page',views.contact_page, name='contact_page'),
    path('profile/', views.user_profile, name='user_profile'),
    path('add_to_cart/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('cart_page/', views.cart_page, name='cart_page'),
    path('checkout/', views.checkout_view, name='checkout'),
    path('cart/remove/<int:item_id>/', views.remove_from_cart, name='remove_from_cart'),

]
