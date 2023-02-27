from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.apple.views import AppleOAuth2Adapter
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.serializers import SocialLoginSerializer
from dj_rest_auth.registration.views import SocialLoginView
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView

from account.api.v1.serializers import UserRegistrationSerializer, MyTokenObtainPairSerializer, UserSerializer


class UserRegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginTokenObtainView(TokenObtainPairView):
    permission_classes = [AllowAny]
    serializer_class = MyTokenObtainPairSerializer


class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    serializer_class = SocialLoginSerializer
    client_class = OAuth2Client
    permission_classes = [AllowAny, ]
    callback_url = "https://developers.google.com/oauthplayground"

    def get_response(self):
        serializer_class = self.get_response_serializer()
        user = self.user
        user_extra_data = SocialAccount.objects.filter(user=self.request.user,
                                                       provider__contains='google').first().extra_data
        user.username = user_extra_data["name"]
        user.save()
        user_detail = UserSerializer(user, many=False, context={"request": self.request})
        serializer = serializer_class(instance=self.token, context={'request': self.request})
        resp = serializer.data
        resp["token"] = resp["key"]
        resp.pop("key")
        resp["user"] = user_detail.data
        return Response(resp, status=status.HTTP_200_OK)


class FacebookLogin(SocialLoginView):
    adapter_class = FacebookOAuth2Adapter
    serializer_class = SocialLoginSerializer
    client_class = OAuth2Client
    permission_classes = [AllowAny, ]

    def get_response(self):
        serializer_class = self.get_response_serializer()
        user = self.user
        user_extra_data = SocialAccount.objects.filter(user=self.request.user,
                                                       provider__contains='facebook').first().extra_data

        user.username = user_extra_data["name"]
        user.save()
        user_detail = UserSerializer(user, many=False, context={"request": self.request})
        serializer = serializer_class(instance=self.token, context={'request': self.request})
        resp = serializer.data
        resp["token"] = resp["key"]
        resp.pop("key")
        resp["user"] = user_detail.data
        return Response(resp, status=status.HTTP_200_OK)


class AppleLogin(SocialLoginView):
    authentication_classes = []
    permission_classes = [AllowAny]
    adapter_class = AppleOAuth2Adapter
    serializer_class = RestSocialLoginSerializer

    def get_response(self):
        serializer_class = self.get_response_serializer()
        user = self.user
        user_detail = UserSerializer(user, many=False)
        serializer = serializer_class(instance=self.token, context={'request': self.request})
        resp = serializer.data
        resp["user"] = user_detail.data
        resp["token"] = resp["key"]
        response = Response(resp, status=status.HTTP_200_OK)
        return response



