from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from users import views

app_name = 'users'

urlpatterns = [
    # join the membership
    path("signup", views.SignupView.as_view(), name="signup"),
    path("signup-restaurant", views.RestaurantSignupView.as_view(), name="signup-restaurant"),
    path("signup-employee", views.EmployeeSignupView.as_view(), name="signup-employee"),
    # log in
    path("signin", views.LoginView.as_view(), name="signin"),
    path("signin-restaurant", views.RestaurantLoginView.as_view(), name="signin-restaurant"),
    path("signin-employee", views.EmployeeLoginView.as_view(), name="signin-employee"),
    path("check-token", views.CheckToken.as_view(), name="CheckToken"),
]
