from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import Product, Cart
from django.contrib.auth.decorators import login_required
import re
from django.contrib.auth.models import User  # Default User model
from .models import Product, Cart
from .models import Cart



User = get_user_model()  # Use custom user model if available

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
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, 'register.html')
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return render(request, 'register.html')

        # Create the user
        user = User.objects.create_user(
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

def login_view(request):
    """Handle user login."""
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Authenticate using email
        try:
            user = User.objects.get(email=email)
            user = authenticate(request, username=user.username, password=password)
        except User.DoesNotExist:
            user = None

        if user is not None:
            login(request, user)
            messages.success(request, "Logged in successfully.")
            return redirect('isLoggedIn')
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
    """Allow admin to add a new product."""
    if not request.session.get('is_admin'):
        return redirect('admin_login')

    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        price = request.POST.get('price')
        category = request.POST.get('category')
        image = request.FILES.get('image')  # Handle uploaded image

        # Validate required fields
        if not name or not price or not category:
            messages.error(request, "All fields are required.")
            return render(request, 'add_product.html')

        # Save the product
        product = Product(name=name, description=description, price=price, category=category, image=image)
        product.save()

        messages.success(request, "Product added successfully!")
        return redirect('admin_dashboard')

    return render(request, 'add_product.html')


def edit_product(request, product_id):
    """Edit an existing product."""
    if not request.session.get('is_admin'):
        return redirect('admin_login')

    product = get_object_or_404(Product, id=product_id)

    if request.method == 'POST':
        product.name = request.POST.get('name')
        product.description = request.POST.get('description')
        product.price = request.POST.get('price')
        product.category = request.POST.get('category')
        if request.FILES.get('image'):
            product.image = request.FILES.get('image')  # Update image if uploaded

        product.save()
        messages.success(request, "Product updated successfully!")
        return redirect('admin_dashboard')

    return render(request, 'edit_product.html', {'product': product})


def delete_product(request, product_id):
    """Delete a product."""
    if not request.session.get('is_admin'):
        return redirect('admin_login')

    product = get_object_or_404(Product, id=product_id)
    product.delete()
    messages.success(request, "Product deleted successfully!")
    return redirect('admin_dashboard')


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

    if quantity > product.quantity_available:
        messages.error(request, f"Only {product.quantity_available} items available.")
        return redirect('product_detail', product_id=product.id)

    # Check if the product is already in the cart
    cart_item, created = Cart.objects.get_or_create(user=request.user, product=product)

    if created:
        cart_item.quantity = quantity
    else:
        cart_item.quantity += quantity

    if cart_item.quantity > product.quantity_available:
        cart_item.quantity = product.quantity_available
        messages.warning(
            request, f"Cart updated to maximum available quantity ({product.quantity_available})."
        )

    cart_item.save()
    messages.success(request, f"Added {cart_item.quantity} x {product.name} to your cart.")
    return redirect('cart_page')

@login_required
def cart_page(request):
    # Get cart items for the logged-in user
    cart_items = CartItem.objects.filter(user=request.user)
    
    # Calculate the total price of the cart
    total_price = sum(item.product.price * item.quantity for item in cart_items)
    
    context = {
        'cart_items': cart_items,
        'total_price': total_price
    }
    return render(request, 'user_cart.html', context)

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
    """Display the user's cart."""
    cart_items = Cart.objects.filter(user=request.user)
    total_price = sum(item.product.price * item.quantity for item in cart_items)
    return render(request, 'user_cart.html', {'cart_items': cart_items, 'total_price': total_price})

def checkout_view(request):
    # Your checkout logic here
    return render(request, 'checkout.html')
from django.http import HttpResponse
def remove_from_cart(request, item_id):
    try:
        # Find the cart item by its ID (using the Cart model)
        item = Cart.objects.get(id=item_id)
        item.delete()  # This will remove the item from the cart
    except Cart.DoesNotExist:
        return HttpResponse('Item not found in the cart', status=404)

    return redirect('cart_page')  # Redirect back to the cart page