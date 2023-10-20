from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage, send_mail
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from app.tokens import generate_token

# Create your views here.


def home(request):
    return render(request, "authentication/index.html")


def signup(request):
    if request.method != "POST":
        return render(request, "authentication/signup.html")

    first_name = request.POST.get("first_name")
    last_name = request.POST.get("last_name")
    email = request.POST.get("email")
    username = request.POST.get("username")
    password = request.POST.get("password1")
    confirm_password = request.POST.get("password2")

    if User.objects.filter(username=username).exists():
        messages.error(
            request, "Username already exists! Please try some other username."
        )
        return redirect("/signup/")

    if User.objects.filter(email=email).exists():
        messages.error(request, "Email already exists!")
        return redirect("/signup/")

    if len(username) > 10 or len(username) <= 3:
        messages.error(request, "Username must be between 4 to 10 characters!")
        return redirect("/signup/")

    if password != confirm_password:
        messages.error(request, "Passwords are not matching.")
        return redirect("/signup/")

    if not username.isalnum():
        messages.error(request, "Username should only contain letters and numbers.")
        return redirect("/signup/")

    user = User.objects.create_user(
        first_name=first_name,
        last_name=last_name,
        email=email,
        username=username,
    )
    user.set_password(password)
    user.is_active = False
    user.save()
    messages.success(
        request,
        "Your account has been successfully created. We have sent you a confirmation email, please confirm your email address in order to activate your account.",
    )

    # Welcome Email
    subject = "Welcome to Coding Mania Solutions Pvt. Ltd."
    message1 = f"""Hi {user.first_name} !!, \nThank you for registering in Coding Mania Solutions Pvt. Ltd. \nWe have also sent you a confirmation email, please confirm your email address in order to activate your account.\n\nThanks & Regards, \nThe Team,\nCoding Mania Solutions Pvt. Ltd."""
    from_email = settings.EMAIL_HOST_USER
    to_list = [user.email]
    send_mail(subject, message1, from_email, to_list, fail_silently=True)

    # Account Activation Email
    current_site = get_current_site(request)
    email_subject = "Confirm your email @Coding Mania Solutions Pvt. Ltd."
    message2 = render_to_string(
        "email_confirmation.html",
        {
            "name": user.first_name,
            "domain": current_site.domain,
            "uid": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": generate_token.make_token(user),
        },
    )
    email = EmailMessage(
        email_subject, message2, settings.EMAIL_HOST_USER, [user.email]
    )
    email.fail_silently = True
    email.send()

    return redirect("/signin/")


def signin(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(username=username, password=password)

        if user is not None and user.is_active:
            login(request, user)
            messages.success(request, "You have been successfully logged in.")
            return render(
                request, "authentication/index.html", {"first_name": user.first_name}
            )
        elif user is not None and user.is_active == False:
            messages.error(
                request,
                "Your account is not activated. Please check your email to activate your account.",
            )
            return redirect("/signin/")
        elif user is None:
            messages.error(request, "Invalid credentials.")
            return redirect("/signin/")

    return render(request, "authentication/signin.html")


def signout(request):
    logout(request)
    messages.success(request, "You have been successfully logged out.")
    return redirect("/signin/")


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and generate_token.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Your account has been successfully activated.")
        return redirect("/signin/")
    else:
        messages.error(
            request,
            "Your account activation link is invalid. Please try again to activate your account.",
        )
        return redirect("/signup/")
