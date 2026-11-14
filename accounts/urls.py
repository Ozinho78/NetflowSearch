from django.contrib.auth import views as auth_views
from django.urls import path

# Namespace: im Template {% url 'accounts:login' %} statt nur 'login'
app_name = "accounts"

urlpatterns = [
    path(
        "login/",
        auth_views.LoginView.as_view(
            template_name="accounts/login.html",
            redirect_authenticated_user=True,   # Eingeloggte nicht erneut zum Login
        ),
        name="login",
    ),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
]