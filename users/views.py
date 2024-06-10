import base64
import os
import random
import string

import pytz
from django.db import transaction
from django.http import JsonResponse
from PIL import Image
import io
import requests
from django.core.files.base import ContentFile
import requests
from datetime import datetime

from django.contrib.auth.hashers import check_password
from django.core.mail import EmailMessage
from django.shortcuts import get_object_or_404, redirect
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import CheckEmail, UserModel
from .serializers import (
    UserSerializer,
    LoginSerializer,
    PostUserSerializer,
    RestaurantSerializer,
    EmployeeSerializer,
)
from django.shortcuts import render
import smtplib
import jwt
from django.conf import settings
from rest_framework import generics, permissions
from restaurant.models import Restaurant, Employee

# Send email
class SendEmail(APIView):
    @swagger_auto_schema(
        tags=["Email Authentication"],
        request_body=PostUserSerializer,
        responses={200: "Success"},
    )
    def post(self, request):
        user_email = request.data.get("email")
        if not user_email:
            return Response(
                {"message": "Please enter your e-mail."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        random_code = "".join(
            random.choices(string.digits, k=6)
        )  # Generate 6-digit random string
        subject = "[HUMASCOT] Membership verification code"
        body = f"Email verification code: {random_code}"  # Add to random code body
        email = EmailMessage(
            subject,
            body,
            to=[user_email],
        )
        email.send()

        # Save authentication code to DB
        code = CheckEmail.objects.create(code=random_code, email=user_email)
        return Response(
            {"message": "Your email has been sent. Please check your mailbox."},
            status=status.HTTP_200_OK,
        )


class CheckEmailView(APIView):
    def post(self, request):
        # # Most recent authentication code instance
        # code_obj = (
        # CheckEmail.objects.filter(email=email).order_by("-created_at").first()
        # )
        # # Check after deployment
        code = request.data.get("code")
        email = request.data.get("email")
        code_obj = CheckEmail.objects.filter(email=email, code=code).first()
        if code_obj is None:
            return Response(
                {"message": "No verification code was sent to that email."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        tz = pytz.timezone("Asia/Vientiane")

        # If the authentication code has expired
        if code_obj.expires_at < datetime.now(tz=tz):
            code_obj.delete()
            return Response(
                {"message": "The verification code has expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        code_obj.delete()  # Delete email verification code
        return Response(
            {"message": "Email verification has been completed.", "is_checked": True},
            status=status.HTTP_200_OK,
        )

class SignupView(APIView):
    @swagger_auto_schema(
        tags=["join the membership"],
        request_body=PostUserSerializer,
        responses={200: "Success"},
    )
    def post(self, request):
        with transaction.atomic():
            category = request.data.get("category")
            email = request.data.get("email")
            code = request.data.get("code")
            password = request.data.get("password")
            password2 = request.data.get("password2")
            profile_image = request.data.get("profile_image")
            code_obj = CheckEmail.objects.filter(email=email, code=code).first()

            # Check whether the password and password match
            if password != password2:
                return JsonResponse(
                    {
                        "message": "Your password and password confirmation do not match."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Check for email duplicates
            user = UserModel.objects.filter(email=email)
            if user.exists():
                return Response(
                    {"message": "The email already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if code_obj is None:
                return Response(
                    {"message": "No verification code was sent to that email."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            tz = pytz.timezone("Asia/Vientiane")

            # If the verification code has expired
            if code_obj.expires_at < datetime.now(tz=tz):
                code_obj.delete()
                return Response(
                    {"message": "The verification code has expired."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Check if your email matches

            if profile_image == "undefined" or profile_image is None:
                # If the image comes as an empty value, use copy to change it!
                # deepcopy -> Import copy module? -> Complete copy! (safe)
                # Consider using try, except -> Additional exception handling!
                data = request.data.copy()
                data["profile_image"] = None
                serializer = UserSerializer(data=data)
            else:
                serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                """
                Add store-specific membership registration logic
                """
                if category != "2":
                    code_obj.delete()  # Delete email verification code
                    serializer.save()
                if category == "2":
                    name = request.data.get("name")
                    address = request.data.get("address")
                    if not name or not address:
                        return Response(
                            {"message": "Please enter all required information."},
                            status.HTTP_400_BAD_REQUEST,
                        )
                    sell_serializer = SellerSerializer(data=request.data)
                    code_obj.delete()  # Delete email verification code
                    if sell_serializer.is_valid():
                        serializer.save(is_seller=True)
                        sell_serializer.save(seller_id=serializer.data.get("id"))
                    else:
                        return Response(
                            {"message": f"{serializer.errors}"},
                            status=status.HTTP_400_BAD_REQUEST,
                        )

                return Response(
                    {"message": "Your registration has been completed."},
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {"message": f"{serializer.errors}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )


class RestaurantSignupView(APIView):
    @swagger_auto_schema(
        tags=["join the membership"],
        request_body=PostUserSerializer,
        responses={200: "Success"},
    )
    def post(self, request):
        with transaction.atomic():
            email = request.data.get("email")
            password = request.data.get("password")
            password2 = request.data.get("password2")
            profile_image = request.data.get("profile_image")

            # Check whether the password and password match
            if password != password2:
                return JsonResponse(
                    {
                        "message": "Your password and password confirmation do not match."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Check for email duplicates
            user = UserModel.objects.filter(email=email)
            if user.exists():
                return Response(
                    {"message": "The email already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if profile_image == "undefined" or profile_image is None:
                # If the image comes as an empty value, use copy to change it!
                # deepcopy -> Import copy module? -> Complete copy! (safe)
                # Consider using try, except -> Additional exception handling!
                data = request.data.copy()
                data["profile_image"] = None
                serializer = UserSerializer(data=data)
            else:
                serializer = UserSerializer(data=request.data)

            if serializer.is_valid():
                name = request.data.get("name")
                address = request.data.get("address")
                if not name or not address:
                    return Response(
                        {"message": "Please enter all required information."},
                        status.HTTP_400_BAD_REQUEST,
                    )
                restaurant_serializer = RestaurantSerializer(data=request.data)
                if restaurant_serializer.is_valid():
                    serializer.save(is_restaurant=True)
                    restaurant_serializer.save(restaurant_id=serializer.data.get("id"))
                else:
                    return Response(
                        {"message": f"{serializer.errors}"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                return Response(
                    {"message": "Your registration has been completed."},
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {"message": f"{serializer.errors}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )


class RestaurantLoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        email = data.get("email")
        password = data.get("password")

        try:
            user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            return Response(data={"message": "Email does not exist."}, status=400)

        if not check_password(password, user.password):
            return Response(data={"message": "Incorrect password."}, status=400)

        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            token = serializer.validated_data['access']
            is_admin = user.is_admin
            is_restaurant = user.is_restaurant
            restaurant = Restaurant.objects.filter(
                restaurant=user
            ).first()  # Use .first() to get the first object.
            restaurant_id = restaurant.id if restaurant else False
            origin_restaurant_name = restaurant.name if restaurant else False

            if is_restaurant == True:
                return Response(
                    data={
                        "token": token,
                        "user_id": user.id,
                        "is_admin": is_admin,
                        "is_restaurant": is_restaurant,
                        "restaurant_id": restaurant_id,
                        "user_name": user.nickname,
                        "origin_restaurant_name": origin_restaurant_name,
                        "email": user.email if user.email else False,
                        "image": (
                            user.profile_image.url if user.profile_image else False
                        ),
                    },
                    status=200,
                )
            else:
                return Response(
                    data={"message": "Your account is not the Restaurant owner!"},
                    status=400,
                )

        else:
            return Response(
                data={
                    "message": "An error occurred. Please contact the administrator."
                },
                status=400,
            )


# Employee
class EmployeeSignupView(APIView):
    @swagger_auto_schema(
        tags=["join the membership"],
        request_body=PostUserSerializer,
        responses={200: "Success"},
    )
    def post(self, request):
        with transaction.atomic():
            email = request.data.get("email")
            password = request.data.get("password")
            password2 = request.data.get("password2")
            profile_image = request.data.get("profile_image")

            # Check whether the password and password match
            if password != password2:
                return JsonResponse(
                    {
                        "message": "Your password and password confirmation do not match."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Check for email duplicates
            user = UserModel.objects.filter(email=email)
            if user.exists():
                return Response(
                    {"message": "The email already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if profile_image == "undefined" or profile_image is None:
                # If the image comes as an empty value, use copy to change it!
                # deepcopy -> Import copy module? -> Complete copy! (safe)
                # Consider using try, except -> Additional exception handling!
                data = request.data.copy()
                data["profile_image"] = None
                serializer = UserSerializer(data=data)
            else:
                serializer = UserSerializer(data=request.data)

            if serializer.is_valid():
                phone = request.data.get("phone")
                address = request.data.get("address")
                if not phone or not address:
                    return Response(
                        {"message": "Please enter all required information."},
                        status.HTTP_400_BAD_REQUEST,
                    )
                employee_serializer = EmployeeSerializer(data=request.data)
                if employee_serializer.is_valid():
                    serializer.save(is_employee=True)
                    employee_serializer.save(employee_id=serializer.data.get("id"))
                else:
                    return Response(
                        {"message": f"{serializer.errors}"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                return Response(
                    {"message": "Your registration has been completed."},
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {"message": f"{serializer.errors}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )


class EmployeeLoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        restaurant_id = data.get("restaurant")
        email = data.get("email")
        password = data.get("password")

        try:
            user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            return Response(data={"message": "Email does not exist."}, status=400)

        if not user.check_password(password):
            return Response(data={"message": "Wrong password."}, status=400)

        try:
            employee = Employee.objects.get(employee=user, restaurant_id=restaurant_id)
        except Employee.DoesNotExist:
            return Response(data={"message": "No employee record found for this restaurant."}, status=400)

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['access']

        return Response(
            data={
                "token": token,
                "user_id": user.id,
                "user_name": user.nickname,
                "is_employee": True,
                "employee_id": employee.id,
                "email": user.email,
                "image": user.profile_image.url if user.profile_image else None,
            },
            status=200,
        )



# normal user log in
class LoginView(TokenObtainPairView):

    def post(self, request, *args, **kwargs):
        data = request.data
        email = data.get("email")
        password = data.get("password")

        try:
            user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            return Response(data={"message": "Email does not exist."}, status=400)

        if not check_password(password, user.password):
            return Response(data={"message": "Wrong password."}, status=400)

        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            token = serializer.validated_data['access']
            is_admin = user.is_admin
            return Response(
                data={
                    "token": token,
                    "user_id": user.id,
                    "is_admin": is_admin,
                    "user_name": user.nickname,
                    "origin_store_name": origin_store_name,
                    "email": user.email if user.email else False,
                    "image": user.profile_image.url if user.profile_image else False,
                },
                status=200,
            )
        else:
            return Response(
                data={
                    "message": "An error occurred. Please contact the administrator."
                },
                status=400,
            )


class CheckToken(APIView):

    def post(self, request):
        try:
            token = request.data.get("token")
            # token decode
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            # Check expiration time
            expiration_time = decoded_token.get("exp")
            return Response({"result": "success"}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            # If the token has expired
            return Response({"result": "fail"}, status=status.HTTP_200_OK)
        except jwt.InvalidTokenError:
            # In case of invalid token
            return Response({"result": "fail"}, status=status.HTTP_200_OK)