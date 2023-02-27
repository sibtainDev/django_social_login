from django.urls import path, include, re_path
from rest_framework import routers
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from account.api.v1.viewsets import UserRegistrationView, LoginTokenObtainView, GoogleLogin, FacebookLogin, AppleLogin

router = routers.SimpleRouter()


urlpatterns = [

    path('', include(router.urls)),
    path('signup/', UserRegistrationView.as_view(), name="signup"),
    path('login/', LoginTokenObtainView.as_view(), name='token_obtain_pair'),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    re_path(r'^login/google/$', GoogleLogin.as_view(), name='google_login'),
    re_path(r'^login/facebook/$', FacebookLogin.as_view(), name='facebook_login'),
    re_path(r'^login/apple/$', AppleLogin.as_view(), name='apple_login'),
    ]
