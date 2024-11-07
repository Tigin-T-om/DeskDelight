from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import Product

User = get_user_model()  # Use the custom user model if available

def index(request):
    chairs = Product.objects.filter(category="chair")  # Filter by 'chair' category
    return render(request, 'index.html', {'chairs': chairs})


def register_page(request):
    return render(request, 'register.html')

def isLoggedIn(request):
    return render(request, 'isLoggedIn.html')

def adminPage(request):
    return render(request, 'admin.html')

def login_page(request):
    return render(request, 'user_login.html')

def cart_page(request):
    return render(request,'user_cart.html')

def product_page(request):
    products = Product.objects.all()  # Fetch all products
    return render(request, 'product.html', {'products': products})

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        phone_number = request.POST.get('phone_number')
        address = request.POST.get('address')

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'register.html')

        # Check if the username is already taken
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, 'register.html')

        # Check if email is already used
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return render(request, 'register.html')

        # Create the user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            phone_number=phone_number,  # Set custom fields
            address=address
        )
        user.save()

        messages.success(request, "Account created successfully. Please log in.")
        return redirect('login_view')  # Redirect to the login page

    return render(request, 'register.html')


def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Authenticate using email (requires custom authentication setup)
        try:
            user = User.objects.get(email=email)
            user = authenticate(request, username=user.username, password=password)
        except User.DoesNotExist:
            user = None

        if user is not None:
            login(request, user)
            messages.success(request, "Logged in successfully.")
            return redirect('isLoggedIn')  # Redirect to the home page after login
        else:
            messages.error(request, "Invalid email or password.")
            return render(request, 'user_login.html')

    return render(request, 'user_login.html')


def logout_view(request):
    logout(request)
    return redirect('index')


