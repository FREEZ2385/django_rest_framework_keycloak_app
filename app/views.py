from django.shortcuts import render
from requests import status_codes
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from app.packages import keycloak
from django.http import HttpResponseRedirect
from django.shortcuts import redirect


# Create your views here.

def KeycloakLoginView(request):
    """
    Keycloakにリダイレクトしてログイン成功後KeycloakLoginSuccessViewに移動
    """
    return redirect(settings.KEYCLOAK_URL + '/auth/realms/' +
                    settings.KEYCLOAK_REALM + '/protocol/openid-connect/auth/'
                    + '?client_id=' + settings.KEYCLOAK_CLIENT
                    + '&response_type=' + settings.KEYCLOAK_RESPONSE_TYPE
                    + '&redirect_url=' + settings.KEYCLOAK_REDIRECT_URL
                    + '&state=' + settings.KEYCLOAK_STATE
                    )


class KeycloakLoginSuccessView(APIView):
    def get(self, request, format=None):
        """
        Keycloak Login Success View (state: Required, session_state: Required, code: Required)
        """
        try:
            params = request.query_params

            # stateのパラメータが足りない場合Errorで返す
            if 'state' not in dict(params.lists()).keys():
                raise Exception("パラメーターが足りないです : state")

            # session_stateのパラメータが足りない場合Errorで返す
            if 'session_state' not in dict(params.lists()).keys():
                raise Exception("パラメーターが足りないです : session_state")

            # codeのパラメータが足りない場合Errorで返す
            if 'code' not in dict(params.lists()).keys():
                raise Exception("パラメーターが足りないです : code")

            # stateが間違っている場合Errorで返す
            if not params['state'] == settings.KEYCLOAK_STATE:
                raise Exception("正常的にURLを移動してなさそうです。改めてご確認ください")

            # アプリを指定
            keycloak_app = keycloak.KeycloakApp()

            # 認証コードでAccess Tokenを取得
            keycloak_app.get_token('authorization_code', {
                                   'code': params['code']})

            # 取得したAccess Tokenが間違っていないか確認
            if keycloak_app.is_token_introspective(keycloak_app.token['access_token']):
                return Response(keycloak_app.token)
            else:
                raise Exception("Keycloakから取ったトークンに問題があります。改めてご確認ください")
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class KeycloakUserLoginCheckView(APIView):
    def get(self, request, format=None):
        """
        Keycloak User Login Check View (aceess_token: Required)
        """
        try:
            params = request.query_params
            # パラメータが足りない場合Errorで返す
            if 'access_token' not in dict(params.lists()).keys():
                raise Exception("パラメーターが足りないです : access_token")

            # アプリを指定
            keycloak_app = keycloak.KeycloakApp()

            # 受けたトークンがまだ活性されている場合TrueでReturnする/非活性ならFalseでReturnする
            if keycloak_app.is_token_introspective(params['access_token']):
                return Response(True)
            else:
                return Response(False)

        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class KeycloakUserAuthView(APIView):
    def get(self, request, format=None):
        """
        Keycloak User Authorized View (id: Required, pw: Required)
        """
        try:
            params = request.query_params
            # パラメータが足りない場合Errorで返す
            if 'id' not in dict(params.lists()).keys():
                raise Exception("パラメーターが足りないです : id")
            if 'password' not in dict(params.lists()).keys():
                raise Exception("パラメーターが足りないです : password")

            # アプリを指定
            keycloak_app = keycloak.KeycloakApp()

            # IDとPasswordでAccess Tokenを取得
            keycloak_app.get_token(
                'password', {'username': params['id'], 'password': params['password']})

            # IDとPasswordが間違っている場合
            if 'error' in keycloak_app.token.keys():
                return Response('ユーザーのIDまたはPasswordが間違っています。改めて入力してください', status=status.HTTP_401_UNAUTHORIZED)

            # 取得したAccess Tokenが間違っていないか確認
            if keycloak_app.is_token_introspective(keycloak_app.token['access_token']):
                return Response(keycloak_app.token)
            else:
                raise Exception("Keycloakから取ったトークンに問題があります。改めてご確認ください")
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class KeycloakUserRefreshView(APIView):
    def get(self, request, format=None):
        """
        Keycloak User Refresh View (refresh_token)
        """
        try:
            params = request.query_params
            # パラメータが足りない場合Errorで返す
            if 'refresh_token' not in dict(params.lists()).keys():
                raise Exception("パラメーターが足りないです : refresh_token")

            # アプリを指定
            keycloak_app = keycloak.KeycloakApp()

            # Refreshが消滅または間違っているか確認
            if not keycloak_app.is_token_introspective(params['refresh_token']):
                raise Exception("Refresh Tokenが消滅されるまたはTokenが間違ってる問題が発生しました。")

            # Refresh TokenでAccess Tokenを取得
            keycloak_app.get_token(
                'refresh_token', {'refresh_token': params['refresh_token']})

            # 取得したAccess Tokenが間違っていないか確認
            if keycloak_app.is_token_introspective(keycloak_app.token['access_token']):
                return Response(keycloak_app.token)
            else:
                raise Exception("Keycloakから取ったトークンに問題があります。改めてご確認ください")
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
