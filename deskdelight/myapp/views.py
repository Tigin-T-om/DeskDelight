from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import Product, Cart
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User  # Default User model
from .models import Product, Cart
from django.http import HttpResponse
import re
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.contrib.auth.models import User
from django.http import JsonResponse
import random


# User = get_user_model()  # Use custom user model if available

# -----------------------------
# Public Views
# -----------------------------

def index(request):
    """Home page displaying gaming chairs."""
    chairs = Product.objects.filter(category="chair")
    return render(request, 'index.html', {'chairs': chairs})

def register_page(request):
    """Render the registration page."""
    return render(request, 'register.html')

def login_page(request):
    """Render the login page."""
    return render(request, 'user_login.html')

def cart_page(request):
    """Render the user cart page."""
    return render(request, 'user_cart.html')

def contact_page(request):
    """Render the contact page."""
    return render(request, 'contact.html')

def product_page(request):
    """Display products filtered by category."""
    category = request.GET.get('category', 'chair')
    products = Product.objects.filter(category=category)
    return render(request, 'product.html', {'products': products, 'category': category})

def product_detail(request, product_id):
    product = get_object_or_404(Product, id=product_id)  # Fetch product by ID
    return render(request, 'product_detail.html', {'product': product})

# -----------------------------
# User Authentication Views
# -----------------------------

def register(request):
    """Handle user registration."""
    if request.method == 'POST':
        fname = request.POST.get("fname")
        lname = request.POST.get("lname")
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        phone_number = request.POST.get('phone_number')
        address = request.POST.get('address')

        # Validate username (alphabets only)
        if not username.isalpha():
            messages.error(request, "Username should only contain alphabetic characters.")
            return render(request, 'register.html')

        # Validate phone number (numeric only)
        if not phone_number.isdigit():
            messages.error(request, "Phone number should only contain numeric characters.")
            return render(request, 'register.html')

        # Validate email
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            messages.error(request, "Please enter a valid email address.")
            return render(request, 'register.html')

        # Validate passwords
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'register.html')

        # Check if username or email already exists
        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, 'register.html')
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return render(request, 'register.html')

        # Create the user
        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        user.first_name = fname
        user.last_name = lname
        user.phone_number = phone_number
        user.address = address
        user.save()

        messages.success(request, "Account created successfully. Please log in.")
        return redirect('login_view')

    return render(request, 'register.html')

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages

CustomUser = get_user_model()  # Dynamically retrieve the active user model

def login_view(request):
    """Handle user and admin login."""
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Authenticate using email
        try:
            user = CustomUser.objects.get(email=email)  # Use CustomUser
            user = authenticate(request, username=user.username, password=password)
        except CustomUser.DoesNotExist:
            user = None

        if user is not None:
            # Check if the user is staff
            if user.is_staff:
                login(request, user)
                messages.success(request, "Admin logged in successfully.")
                return redirect('adminPage')  # Redirect to admin dashboard
            else:
                login(request, user)
                messages.success(request, "Logged in successfully.")
                return redirect('isLoggedIn')  # Redirect to user dashboard or home
        else:
            messages.error(request, "Invalid email or password.")
            return render(request, 'user_login.html')

    return render(request, 'user_login.html')


def logout_view(request):
    """Handle user logout."""
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect('index')

# -----------------------------
# Authenticated User Views
# -----------------------------

@login_required
def isLoggedIn(request):
    """Render a page showing the user is logged in."""
    return render(request, 'isLoggedIn.html')

@login_required
def user_profile(request):
    """Allow users to view and update their profile."""
    if request.method == 'POST':
        user = request.user
        user.username = request.POST.get('username')
        user.email = request.POST.get('email')
        user.phone_number = request.POST.get('phone_number')
        user.address = request.POST.get('address')
        user.save()

        messages.success(request, "Your profile has been updated successfully.")
        return redirect('user_profile')

    return render(request, 'user_profile.html', {'user': request.user})

# -----------------------------
# Admin Views (if needed)
# -----------------------------

def adminPage(request):
    """Render a custom admin page."""
    return render(request, 'admin.html')

# Custom admin login details
ADMIN_CREDENTIALS = {
    "username": "admin",
    "password": "123"
}

# -----------------------------
# Admin-Specific Views
# -----------------------------

def admin_login(request):
    """Custom admin login."""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Validate custom admin credentials
        if username == ADMIN_CREDENTIALS['username'] and password == ADMIN_CREDENTIALS['password']:
            # Mark as logged in admin (simple flag in session)
            request.session['is_admin'] = True
            messages.success(request, "Welcome Admin!")
            return redirect('admin_dashboard')
        else:
            messages.error(request, "Invalid admin credentials.")
            return render(request, 'admin_login.html')

    return render(request, 'admin_login.html')

def admin_logout(request):
    """Logout admin."""
    request.session['is_admin'] = False  # Remove admin session flag
    messages.success(request, "Admin logged out successfully.")
    return redirect('admin_login')

def admin_dashboard(request):
    """Admin dashboard to manage users and products."""
    if not request.session.get('is_admin'):
        return redirect('admin_login')  # Restrict access to logged-in admin only

    products = Product.objects.all()
    users = User.objects.exclude(username='admin')  # Exclude admin user
    return render(request, 'admin_dashboard.html', {'products': products, 'users': users})

def add_product(request):
    """Allow custom admin to add a new product."""
    if not request.user.is_authenticated or not request.user.is_staff:
        messages.error(request, "You are not authorized to add products.")
        return redirect('admin_login')

    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        price = request.POST.get('price')
        category = request.POST.get('category')
        quantity_available = request.POST.get('quantity_available')
        image = request.FILES.get('image')  # Handle uploaded image

        # Validate required fields
        if not name or not price or not category or not quantity_available:
            messages.error(request, "All fields are required.")
            return render(request, 'admin_add_product.html')

        # Save the product
        product = Product(
            name=name,
            description=description,
            price=price,
            category=category,
            quantity_available=quantity_available,
            image=image
        )
        product.save()

        messages.success(request, "Product added successfully!")
        return redirect('product_management')

    return render(request, 'admin_add_product.html')

def edit_product(request, product_id):
    """Allow custom admin to edit an existing product."""
    if not request.user.is_authenticated or not request.user.is_staff:
        messages.error(request, "You are not authorized to edit products.")
        return redirect('admin_login')

    product = get_object_or_404(Product, id=product_id)

    if request.method == 'POST':
        product.name = request.POST.get('name')
        product.description = request.POST.get('description')
        product.price = request.POST.get('price')
        product.category = request.POST.get('category')
        product.quantity_available = request.POST.get('quantity_available')
        if request.FILES.get('image'):
            product.image = request.FILES.get('image')  # Update image if uploaded

        product.save()
        messages.success(request, "Product updated successfully!")
        return redirect('product_management')

    return render(request, 'admin_product_edit.html', {'product': product})


def delete_product(request, product_id):
    """Allow custom admin to delete a product."""
    if not request.user.is_authenticated or not request.user.is_staff:
        messages.error(request, "You are not authorized to delete products.")
        return redirect('admin_login')

    product = get_object_or_404(Product, id=product_id)
    product.delete()
    messages.success(request, "Product deleted successfully!")
    return redirect('product_management')

def product_management(request):
    """Display a list of products for the admin."""
    if not request.user.is_authenticated or not request.user.is_staff:
        messages.error(request, "You are not authorized to view this page.")
        return redirect('admin_login')

    products = Product.objects.all()
    return render(request, 'admin_product_management.html', {'products': products})

def manage_users(request):
    """Allow admin to manage users (activate/deactivate)."""
    if not request.session.get('is_admin'):
        return redirect('admin_login')

    users = User.objects.exclude(username='admin')

    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        action = request.POST.get('action')  # 'activate' or 'deactivate'
        user = get_object_or_404(User, id=user_id)

        if action == 'activate':
            user.is_active = True
            messages.success(request, f"User {user.username} activated successfully!")
        elif action == 'deactivate':
            user.is_active = False
            messages.success(request, f"User {user.username} deactivated successfully!")

        user.save()

    return render(request, 'manage_users.html', {'users': users})

@login_required
def add_to_cart(request, product_id):
    """Add a product to the cart."""
    product = get_object_or_404(Product, id=product_id)
    quantity = int(request.POST.get('quantity', 1))

    # Ensure the requested quantity does not exceed stock
    if quantity > product.quantity_available:
        messages.error(request, f"Only {product.quantity_available} items available.")
        return redirect('product_detail', product_id=product.id)

    # Check if the product is already in the cart
    cart_item, created = Cart.objects.get_or_create(user=request.user, product=product)

    if created:
        cart_item.quantity = quantity
    else:
        cart_item.quantity += quantity

    # Cap the cart quantity to available stock
    if cart_item.quantity > product.quantity_available:
        cart_item.quantity = product.quantity_available
        messages.warning(
            request, f"Cart updated to maximum available quantity ({product.quantity_available})."
        )
    cart_item.save()
    messages.success(request, f"Added {cart_item.quantity} x {product.name} to your cart.")
    return redirect('cart_page')


@login_required
def admin_set_quantity(request, product_id):
    """Admin sets the quantity of a product."""
    product = get_object_or_404(Product, id=product_id)

    if request.method == "POST":
        quantity = int(request.POST.get('quantity', 0))
        product.quantity_available = quantity
        product.save()
        messages.success(request, f"Updated quantity for {product.name} to {quantity}.")
        return redirect('admin_dashboard')

    return render(request, 'set_quantity.html', {'product': product})

@login_required
def cart_page(request):
    cart_items = Cart.objects.filter(user=request.user, status='active')
    total_price = sum(item.product.price * item.quantity for item in cart_items)
    return render(request, 'user_cart.html', {'cart_items': cart_items, 'total_price': total_price})



def checkout_view(request):
    # Your checkout logic here
    return render(request, 'checkout.html')

def remove_from_cart(request, item_id):
    try:
        # Find the cart item by its ID (using the Cart model)
        item = Cart.objects.get(id=item_id)
        item.delete()  # This will remove the item from the cart
    except Cart.DoesNotExist:
        return HttpResponse('Item not found in the cart', status=404)

    return redirect('cart_page')  # Redirect back to the cart page

# Store OTP temporarily (or better use a model for persistence)
otp_storage = {}

# Forgot Password: Send OTP
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if User.objects.filter(email=email).exists():
            otp = get_random_string(length=6, allowed_chars='1234567890')  # Generate numeric OTP
            otp_storage[email] = otp
            send_mail(
                'Your OTP for Password Reset',
                f'Your OTP is {otp}.',
                'noreply@deskdelight.com',
                [email],
                fail_silently=False,
            )
            messages.success(request, 'OTP sent to your email!')
            return redirect('verify_otp')
        else:
            messages.error(request, 'Email not found.')
    return render(request, 'forgot_password.html')


def send_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        
        # Check if email exists in the system
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "Email not registered!")
            return redirect('forgot_password_page')
        
        # Generate OTP
        otp = random.randint(100000, 999999)

        # Send OTP to user's email
        subject = 'Password Reset OTP'
        message = f'Your OTP for password reset is {otp}'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        try:
            send_mail(subject, message, from_email, recipient_list)
            request.session['otp'] = otp  # Store OTP in session for verification
            request.session['email'] = email  # Store email for verification
            return redirect('verify_otp')  # Redirect to OTP verification page
        except Exception as e:
            messages.error(request, "Error sending OTP. Please try again.")
            return redirect('forgot_password_page')
    return render(request, 'send_otp.html')

from django.contrib.auth import get_user_model

def forgot_password_page(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        # Use the custom user model
        if CustomUser.objects.filter(email=email).exists():
            # Generate OTP
            otp = random.randint(100000, 999999)

            # Save OTP and email in session
            request.session['otp'] = otp
            request.session['email'] = email

            # Send OTP email
            try:
                send_mail(
                    'Your OTP for Password Reset',
                    f'Your OTP is {otp}.',
                    'noreply@deskdelight.com',
                    [email],
                    fail_silently=False,
                )
                messages.success(request, 'OTP sent to your email!')
                return redirect('verify_otp')  # Redirect to OTP verification page
            except Exception as e:
                messages.error(request, 'Failed to send OTP. Please try again.')
        else:
            messages.error(request, 'Email not found.')
    return render(request, 'forgot_password.html')


# Verify OTP Page
def verify_otp(request):
    if request.method == 'POST':
        email = request.session.get('email')
        entered_otp = request.POST.get('otp')

        # Validate OTP
        if email and int(entered_otp) == request.session.get('otp'):
            messages.success(request, 'OTP verified! Reset your password.')
            return redirect('reset_password')
        else:
            messages.error(request, 'Invalid OTP or email.')
    return render(request, 'verify_otp.html')


# Reset Password Page
def reset_password(request):
    if request.method == 'POST':
        email = request.session.get('email')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password == confirm_password:
            try:
                user = CustomUser.objects.get(email=email)
                user.set_password(new_password)
                user.save()

                messages.success(request, 'Password successfully reset. You can now log in.')
                return redirect('login_page')  # Redirect to login page
            except CustomUser.DoesNotExist:
                messages.error(request, 'User does not exist.')
        else:
            messages.error(request, 'Passwords do not match.')

    return render(request, 'reset_password.html')

def is_admin(user):
    return user.is_staff

from django.contrib.auth.decorators import login_required, user_passes_test

@login_required
@user_passes_test(is_admin)
def user_management(request):
    """Display all users and allow admin to delete users."""
    users = CustomUser.objects.filter(is_staff=False)  # Exclude admins
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        try:
            user_to_delete = CustomUser.objects.get(id=user_id)
            user_to_delete.delete()
            messages.success(request, "User deleted successfully.")
        except CustomUser.DoesNotExist:
            messages.error(request, "User not found.")
        return redirect('user_management')
    
    return render(request, 'admin_user_management.html', {'users': users})
from myapp.models import Order  
from myapp.models import Order  # Make sure the Order model is defined in models.py

@login_required
def admin_order_management(request):
    if not request.user.is_staff:
        messages.error(request, "You are not authorized to view this page.")
        return redirect('admin_login')

    orders = Order.objects.prefetch_related('orderitem_set', 'customer').order_by('-created_at')
    return render(request, 'admin_order_management.html', {'orders': orders})

@login_required
def update_order_status(request, order_id):
    """Update the status of an order."""
    if not request.user.is_staff:
        messages.error(request, "You are not authorized to update orders.")
        return redirect('admin_login')

    order = get_object_or_404(Order, id=order_id)

    if request.method == 'POST':
        status = request.POST.get('status')
        if status:
            order.status = status
            order.save()
            messages.success(request, f"Order status updated to {status}.")
        else:
            messages.error(request, "Invalid status update.")

        return redirect('admin_order_management')

    return render(request, 'admin_update_order.html', {'order': order})

from django import forms
from django.shortcuts import render, redirect
from django.contrib import messages
from django.db import transaction
from django.contrib.auth.decorators import login_required
from .models import Cart, Order, OrderItem

# Form for capturing shipping address
class ShippingAddressForm(forms.Form):
    address = forms.CharField(label="Shipping Address", widget=forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}))
    phone_number = forms.CharField(label="Phone Number", max_length=15, widget=forms.TextInput(attrs={'class': 'form-control'}))

@login_required
def proceed_to_checkout(request):
    """Handle the checkout process and place an order."""
    cart_items = Cart.objects.filter(user=request.user)

    if not cart_items:
        messages.error(request, "Your cart is empty!")
        return redirect('cart_page')

    total_price = sum(item.product.price * item.quantity for item in cart_items)

    with transaction.atomic():
        order = Order.objects.create(
            customer=request.user,
            total_price=total_price,
            status='Pending'
        )

        for item in cart_items:
            # Reduce stock
            item.product.quantity_available -= item.quantity
            item.product.save()

            OrderItem.objects.create(
                order=order,
                product=item.product,
                quantity=item.quantity,
                total_price=item.product.price * item.quantity
            )

        cart_items.delete()

    messages.success(request, "Your order has been placed successfully!")
    return redirect('order_confirmation', order_id=order.id)

@login_required
def order_confirmation(request, order_id):
    """Display order details after placing an order."""
    order = get_object_or_404(Order, id=order_id, customer=request.user)
    order_items = OrderItem.objects.filter(order=order)

    return render(request, 'order_confirmation.html', {
        'order': order,
        'order_items': order_items,
    })

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Cart

@login_required
def remove_from_cart(request, item_id):
    try:
        # Find the cart item by its ID (using the Cart model)
        item = Cart.objects.get(id=item_id, user=request.user)
        
        # If quantity is greater than 1, reduce the quantity by 1
        if item.quantity > 1:
            item.quantity -= 1
            item.save()
            messages.success(request, f"One {item.product.name} has been removed from your cart.")
        else:
            item.delete()  # If quantity is 1, remove the entire item from the cart
            messages.success(request, f"{item.product.name} has been removed from your cart.")
        
    except Cart.DoesNotExist:
        return HttpResponse('Item not found in the cart', status=404)

    return redirect('cart_page')  # Redirect back to the cart page

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Order

@login_required
def order_confirmation(request, order_id):
    order = get_object_or_404(Order, id=order_id, customer=request.user)
    return render(request, 'order_confirmation.html', {'order': order})

        
@login_required
def track_order_page(request):
    user = request.user
    orders = Order.objects.filter(customer=user)
    return render(request, 'track_order.html', {'orders': orders})


@login_required
def checkout_page(request):
    user = request.user
    cart_items = Cart.objects.filter(user=user)
    total_price = sum(item.product.price * item.quantity for item in cart_items)

    if not cart_items.exists():
        return redirect('cart_page')  # Redirect to cart if empty

    return render(request, 'checkout.html', {'cart_items': cart_items, 'total_price': total_price})

@login_required
def place_order(request):
    if request.method == "POST":
        user = request.user
        shipping_address = request.POST.get('shipping_address')
        phone_number = request.POST.get('phone_number')
        payment_method = request.POST.get('payment_method')

        cart_items = Cart.objects.filter(user=user)
        total_price = sum(item.product.price * item.quantity for item in cart_items)

        # Create Order
        order = Order.objects.create(
            customer=user,
            total_price=total_price,
            status="Pending",
            shipping_address=shipping_address,
            phone_number=phone_number,
        )

        # Add Order Items
        for item in cart_items:
            OrderItem.objects.create(
                order=order,
                product=item.product,
                quantity=item.quantity,
                total_price=item.product.price * item.quantity,
            )

        # Clear the Cart
        cart_items.delete()

        # Redirect to Track Order Page
        return redirect('track_order_page')

    return redirect('checkout_page')
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Cart, Order, OrderItem
from django.contrib import messages

@login_required
def checkout(request):
    user = request.user
    cart_items = Cart.objects.filter(user=user)
    total_price = sum(item.product.price * item.quantity for item in cart_items)

    if request.method == 'POST':
        # Get the submitted shipping address and phone number
        shipping_address = request.POST.get('shipping_address')
        phone_number = request.POST.get('phone_number')

        if not shipping_address or not phone_number:
            messages.error(request, "Please fill in all required fields.")
            return redirect('checkout_page')

        # Create the order
        order = Order.objects.create(
            customer=user,
            total_price=total_price,
            shipping_address=shipping_address,
            phone_number=phone_number,
        )

        # Add items to the order
        for item in cart_items:
            OrderItem.objects.create(
                order=order,
                product=item.product,
                quantity=item.quantity,
                total_price=item.product.price * item.quantity,
            )
        
        # Clear the user's cart
        cart_items.delete()

        # Redirect to the track order page
        return redirect('track_order_page')
    
    return redirect('checkout_page')  # If not POST, redirect to checkout page

