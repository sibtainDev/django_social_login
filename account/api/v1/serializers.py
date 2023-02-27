from allauth.socialaccount.helpers import complete_social_login
from dj_rest_auth.registration.serializers import SocialLoginSerializer
from django.contrib.auth import get_user_model
from allauth.account import app_settings as allauth_settings
from requests import HTTPError
from rest_framework import serializers
from rest_framework_simplejwt import exceptions
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from setuptools._entry_points import _

from account.models import User
from utils.helper import check_email


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password', 'username']

    def create(self, validated_data):
        user = User(
            username=validated_data.get('email').split('@')[0],
            email=validated_data.get('email'),
            first_name=validated_data.get("first_name"),
            last_name=validated_data.get("last_name"),
        )
        user.set_password(validated_data.get('password'))
        user.save()
        return user


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['username'] = user.username
        token['email'] = user.email

        return token

    def validate(self, attrs):
        user_name = attrs.get("email")
        password = attrs.get("password")

        if check_email(user_name) is False:
            try:
                user = User.objects.get(Q(username=user_name) | Q(phone=user_name))
                if user.check_password(password):
                    attrs['email'] = user.email

                """
                 In my case, I used the Email address as the default Username 
                 field in my custom User model. so that I get the user email 
                 from the Users model and set it to the attrs field. You can 
                 be modified as your setting and your requirement 
                """

            except User.DoesNotExist:
                raise exceptions.AuthenticationFailed(
                    'No such user with provided credentials'.title())

        data = super().validate(attrs)
        return data


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"


class RestSocialLoginSerializer(SocialLoginSerializer):
    id_token = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        view = self.context.get('view')
        request = self._get_request()

        if not view:
            raise serializers.ValidationError(
                _("View is not defined, pass it as a context variable")
            )

        adapter_class = getattr(view, 'adapter_class', None)
        if not adapter_class:
            raise serializers.ValidationError(_("Define adapter_class in view"))

        adapter = adapter_class(request)
        app = adapter.get_provider().get_app(request)

        # More info on code vs access_token
        # http://stackoverflow.com/questions/8666316/facebook-oauth-2-0-code-and-token

        # Case 1: We received the access_token
        if attrs.get('access_token'):
            access_token = attrs.get('access_token')

        # Case 2: We received the authorization code
        elif attrs.get('code'):
            self.callback_url = getattr(view, 'callback_url', None)
            self.client_class = getattr(view, 'client_class', None)

            if not self.callback_url:
                raise serializers.ValidationError(
                    _("Define callback_url in view")
                )
            if not self.client_class:
                raise serializers.ValidationError(
                    _("Define client_class in view")
                )

            code = attrs.get('code')

            provider = adapter.get_provider()
            scope = provider.get_scope(request)
            client = self.client_class(
                request,
                app.client_id,
                app.secret,
                adapter.access_token_method,
                adapter.access_token_url,
                self.callback_url,
                scope
            )
            token = client.get_access_token(code)
            access_token = token['access_token']

        else:
            raise serializers.ValidationError(
                _("Incorrect input. access_token or code is required."))

        social_token = social_token = adapter.parse_token({
            'access_token': access_token,
            'id_token': attrs.get('id_token')  # For apple login
        })
        social_token.app = app

        try:
            login = self.get_social_login(adapter, app, social_token, access_token)
            complete_social_login(request, login)
        except HTTPError:
            raise serializers.ValidationError(_("Incorrect value"))

        if not login.is_existing:
            # We have an account already signed up in a different flow
            # with the same email address: raise an exception.
            # This needs to be handled in the frontend. We can not just
            # link up the accounts due to security constraints
            if allauth_settings.UNIQUE_EMAIL:
                # Do we have an account already with this email address?
                account_exists = get_user_model().objects.filter(
                    email=login.user.email,
                ).exists()
                if account_exists:
                    raise serializers.ValidationError(
                        _("User is already registered with this e-mail address.")
                    )

            login.lookup()
            login.save(request, connect=True)

        attrs['user'] = login.account.user

        return attrs
