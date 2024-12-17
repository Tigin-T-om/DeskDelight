from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name="index"),
    path('register_page', views.register_page, name="register_page"),
    path('register', views.register, name="register"),
    path('login_page', views.login_page, name="login_page"),
    path('login_view', views.login_view, name="login_view"),
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
    path('remove-from-cart/<int:item_id>/', views.remove_from_cart, name='remove_from_cart'),


    # Password Reset URLs
    path('forgot_password/', views.forgot_password_page, name='forgot_password_page'),
    path('send_otp/', views.send_otp, name='send_otp'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('reset_password/', views.reset_password, name='reset_password'),

    path('user_management/', views.user_management, name='user_management'),

    path('product_management/', views.product_management, name='product_management'),
    path('add_product/', views.add_product, name='add_product'),
    path('edit_product/<int:product_id>/', views.edit_product, name='edit_product'),
    path('delete_product/<int:product_id>/', views.delete_product, name='delete_product'),

    path('checkout/', views.proceed_to_checkout, name='checkout'),
    path('custom_admin/order_management/', views.admin_order_management, name='admin_order_management'),
    path('custom_admin/update_order/<int:order_id>/', views.update_order_status, name='update_order_status'),
    # path('checkout/', views.proceed_to_checkout, name='checkout'),
    path('order_confirmation/<int:order_id>/', views.order_confirmation, name='order_confirmation'),
    path('remove_from_cart/<int:item_id>/', views.remove_from_cart, name='remove_from_cart'),
    path('checkout/', views.checkout, name='checkout'),
    path('order-confirmation/<int:order_id>/', views.order_confirmation, name='order_confirmation'),
    path('checkout/', views.checkout_page, name='checkout_page'),  # Use 'checkout_page' view
    path('place_order/', views.place_order, name='place_order'),
    path('track_order/', views.track_order_page, name='track_order_page'),
    path('order/cancel/<int:order_id>/', views.cancel_order, name='cancel_order'),
    path('products/', views.product_list, name='product_list'),
    path('search_results/', views.search_results, name='search_results'),
    path('update-cart-quantity/', views.update_cart_quantity, name='update_cart_quantity'),
]


    # path('checkout/', views.checkout, name='checkout'),
    # path('order/confirmation/<int:order_id>/', views.order_confirmation, name='order_confirmation'),
    # path('checkout/', views.checkout, name='checkout'),
    # path('order-confirmation/<int:order_id>/', views.order_confirmation, name='order_confirmation'),
    # path('order_confirmation/<int:order_id>/', views.order_confirmation, name='order_confirmation'),
