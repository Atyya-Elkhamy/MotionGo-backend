import random
import requests
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers, status, permissions
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.hashers import check_password
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer
from .models import User
from django.core.mail import EmailMultiAlternatives
User = get_user_model()


# ------------------- Custom Login -------------------

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "No user with this email."})

        if not user.check_password(password):
            raise serializers.ValidationError({"password": "Incorrect password."})

        refresh = self.get_token(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            }
        }

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


# ------------------- Register -------------------

class CreateUserView(APIView):
    def get(self, request):
        users = User.objects.all()
        if not users.exists():
            return Response({"response": "No users found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ------------------- Logout -------------------

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)


# ------------------- Google Auth (Login or Signup) -------------------

class GoogleAuthView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        access_token = request.data.get("access_token")
        if not access_token:
            return Response({"error": "Access token is required."}, status=400)

        response = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )

        if response.status_code != 200:
            return Response({"error": "Invalid Google token."}, status=400)

        google_data = response.json()
        email = google_data.get("email")
        full_name = google_data.get("name", "")

        if not email:
            return Response({"error": "Email not returned from Google."}, status=400)

        try:
            user = User.objects.get(email=email)
            created = False
        except User.DoesNotExist:
            # Create new user
            base_username = full_name.replace(" ", "") or email.split("@")[0]
            username = base_username
            count = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{count}"
                count += 1

            user = User.objects.create_user(
                username=username,
                email=email,
            )
            user.is_verified = True
            user.save()
            created = True

        refresh = RefreshToken.for_user(user)
        return Response({
            "message": "Signup successful" if created else "Login successful",
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            }
        }, status=201 if created else 200)


# ------------------- OTP Email -------------------

def send_otp_email(email, otp, message):
    # subject = 'Your OTP Code'
    # full_message = f'{message} : {otp}'
    # from_email = settings.EMAIL_HOST_USER
    # recipient_list = [email]
    # return send_mail(subject, full_message, from_email, recipient_list)
    subject = 'Your OTP Code'
    from_email = settings.DEFAULT_FROM_EMAIL
    message='Your OTP to Change Password Is '
    recipient_list = [email]
    text_content = f'{message}: {otp}'
    html_content = f"""
        <p>{message}:</p>
        <h2 style="color:#2E86C1;">{otp}</h2>
        <p>This OTP is valid for 10 minutes.</p>
        """

    msg = EmailMultiAlternatives(subject, text_content, from_email, recipient_list)
    msg.attach_alternative(html_content, "text/html")
    return msg.send()

class SendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required."}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=404)

        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.expired_at = timezone.now() + timezone.timedelta(minutes=10)
        user.save()

        send_otp_email(user.email, otp, message="Your login code is")
        return Response({"message": f"OTP sent to {user.email}"}, status=200)


class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)


class OTPVerificationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            try:
                user = User.objects.get(email=email, otp=otp)
                if user.expired_at and timezone.now() > user.expired_at:
                    return Response({"error": "OTP expired."}, status=400)

                user.is_verified = True
                user.otp = None
                user.expired_at = None
                user.save()
                return Response({"message": "OTP verified successfully."}, status=200)
            except User.DoesNotExist:
                return Response({"error": "Invalid OTP or email."}, status=400)

        return Response(serializer.errors, status=400)

class ChangePasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        new_password = request.data.get('new_password')

        if not email or not new_password:
            return Response({"error": "Email and new password are required."}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=404)

        # 🔐 Check if the OTP was verified
        if not user.is_verified:
            return Response({"error": "OTP not verified."}, status=400)

        # Optional: validate password strength
        if len(new_password) < 8:
            return Response({"error": "Password must be at least 8 characters."}, status=400)

        user.set_password(new_password)
        user.is_verified = False  # Reset verification flag
        user.otp = None
        user.expired_at = None
        user.save()

        return Response({"message": "Password updated successfully."}, status=200)


class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"message": "Account deleted successfully."}, status=status.HTTP_200_OK)