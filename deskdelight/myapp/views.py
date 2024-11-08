from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import Product
from django.contrib.auth.decorators import login_required

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

def contact_page(request):
    return render(request, 'contact.html')

def product_page(request):
    # Get the category from the query parameters (optional, default to 'chair')
    category = request.GET.get('category', 'chair')
    
    # Filter products based on the selected category
    products = Product.objects.filter(category=category)
    
    return render(request, 'product.html', {'products': products, 'category': category})

def register(request):
    if request.method == 'POST':
        fname = request.POST.get("fname")
        lname = request.POST.get("lname")
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
        user.first_name = fname
        user.last_name = lname
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


@login_required
def user_profile(request):
    if request.method == 'POST':
        # Get current user
        user = request.user

        # Update user details
        user.username = request.POST.get('username')
        user.email = request.POST.get('email')
        user.phone_number = request.POST.get('phone_number')
        user.address = request.POST.get('address')

        # Save the updated details
        user.save()
        
        messages.success(request, "Your profile has been updated successfully.")
        return redirect('user_profile')  # Redirect to profile page

    # Show user profile details
    return render(request, 'user_profile.html', {'user': request.user})