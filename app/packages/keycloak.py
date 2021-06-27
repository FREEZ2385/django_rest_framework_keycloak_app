import requests
from django.conf import settings


class KeycloakApp():
    def __init__(self):
        self.token = {}

    def get_cert(self):
        response = requests.get(settings.KEYCLOAK_URL + '/auth/realms/' +
                                settings.KEYCLOAK_REALM + '/protocol/openid-connect/certs',
                                )

        print(response.json())

    def get_conf(self):
        response = requests.get(settings.KEYCLOAK_URL + '/auth/realms/' +
                                settings.KEYCLOAK_REALM + '/.well-known/openid-configuration',
                                )

        print(response.json())

    def get_token(self, grant_type, data):
        data['grant_type'] = grant_type
        data['client_id'] = settings.KEYCLOAK_CLIENT
        data['client_secret'] = settings.KEYCLOAK_CLIENT_SECRET
        response = requests.post(settings.KEYCLOAK_URL + '/auth/realms/' +
                                 settings.KEYCLOAK_REALM + '/protocol/openid-connect/token/',
                                 data
                                 )
        self.token = response.json()

    def is_token_introspective(self, token):
        response = requests.post(settings.KEYCLOAK_URL + '/auth/realms/' +
                                 settings.KEYCLOAK_REALM + '/protocol/openid-connect/token/introspect/',
                                 {
                                     'client_id': settings.KEYCLOAK_CLIENT,
                                     'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
                                     'token': token,
                                 }
                                 )
        result = response.json()
        return result['active']
