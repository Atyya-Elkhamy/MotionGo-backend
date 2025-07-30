from django.urls import path
from .views import * 
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView 

urlpatterns = [

    path("login/", CustomTokenObtainPairView.as_view(), name="login_view"),
    path("refresh/", TokenRefreshView.as_view(), name="refresh_view"),
    path("create/", CreateUserView.as_view(), name="create_user"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path('google/',  GoogleAuthView.as_view(), name='google-auth'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path("send-otp/", SendOTPView.as_view(), name="send_otp"),
    path("verify-otp/", OTPVerificationView.as_view(), name="verify_otp"),
    path("reset-password/", ChangePasswordView.as_view(), name="reset_password"),
    path('delete/', DeleteAccountView.as_view(), name='delete-account'),

   
]
