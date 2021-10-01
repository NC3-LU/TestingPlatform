from django.core.files.storage import FileSystemStorage
from decouple import config
import secrets
import requests
import json
import jwt
from django.core.signing import Signer


def generate_nonce():
    return secrets.token_urlsafe()


def iot_api_login():
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer TOKEN'
    }
    payload = json.dumps({"client_id": config('IOT_CLIENT_ID'), "nonce": f"{generate_nonce()}",
                          "email": config('EMAIL'), "password": config('PASSWORD')})
    endpoint = config('IOT_API_URL') + 'authorize'
    id_token = requests.post(endpoint, headers=headers, data=payload).json()['id_token']
    tenant_id = jwt.decode(id_token, options={"verify_signature": False},
                           audience='NeSPys5jIT_3OKn7R_ZyBqPubkDl9amI3sGOxJLXCy4')['https://www.iot-inspector.com/tenants'][0]['id']

    payload = json.dumps({"client_id": config('IOT_CLIENT_ID'), "nonce": f"{generate_nonce()}",
                          "id_token": id_token, 'tenant_id': tenant_id})
    endpoint = config('IOT_API_URL') + 'token'
    response = requests.post(endpoint, headers=headers, data=payload).json()
    return response


def iot_add_user(iotuser, token):
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    endpoint = config('IOT_API_URL') + 'add-user'
    signer = Signer()
    payload = {'email': iotuser.user.email, 'password': signer.unsign_object(iotuser.password), 'policy': True,
               'company_name': iotuser.user.company_name}
    response = requests.post(endpoint, headers=headers, data=payload)
    return response.json()


def get_product_group_id(client):
    query = """
    query {
        allProductGroups {
            id
            name
        }
    }
    """
    res = client.query(query)
    return next(pg for pg in res["allProductGroups"] if pg["name"] == "Default")['id']


def get_fs_storage(user_id):
    return FileSystemStorage(location=f"{config('FILES')}/user_{user_id}/")
