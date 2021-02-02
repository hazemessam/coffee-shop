import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


# AUTH0_DOMAIN = 'udacity-fsnd.auth0.com'
AUTH0_DOMAIN = 'heq.us.auth0.com'
AUTH0_ISSUER = 'https://heq.us.auth0.com/'
ALGORITHMS = ['RS256']
# API_AUDIENCE = 'dev'
API_AUDIENCE = 'coffee-api'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():
    auth_header = request.headers.get('Authorization', None)
    if auth_header is None:
        raise AuthError(
            {
                'code': 'unauthorized',
                'description': 'auth header is missing'
            }, 401
        )
    
    auth_header_parts = auth_header.split(' ')
    if len(auth_header_parts) != 2 or auth_header_parts[0].lower() != 'bearer':
        raise AuthError(
            {
                'code': 'unauthorized',
                'description': 'auth header is malformed'
            }, 401
        )

    return auth_header_parts[1]


'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    permissions = payload.get('permissions', None)
    if permissions is None:
        raise AuthError(
            {
                'code': 'unauthorized',
                'description': 'permissions are not included in the payload'
            }, 401
        )
    
    if permission not in permissions:
        raise AuthError(
            {
                'code': 'unauthorized',
                'description': 'requested permission is not in the payload permissions array'
            }, 401
        )
    
    return True


'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    kid = None
    try:
        unverified_headers = jwt.get_unverified_headers(token)
        kid = unverified_headers.get('kid', None)
    except jwt.JWTError:
        raise AuthError(
            {
                'code': 'unauthorized',
                'description': 'it should be an Auth0 token with key id (kid)'
            }, 401
        )

    if kid is None:
        raise AuthError(
            {
                'code': 'unauthorized',
                'description': 'it should be an Auth0 token with key id (kid)'
            }, 401
        )
    
    jwks_json = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jwks_json.read())

    rsa_key = {}
    for jwk in jwks['keys']:
        if jwk['kid'] == kid:
            rsa_key['kty'] = jwk['kty']
            rsa_key['kid'] = jwk['kid']
            rsa_key['use'] = jwk['use']
            rsa_key['n'] = jwk['n']
            rsa_key['e'] = jwk['e']

    if rsa_key:
        try:
            payload = jwt.decode(
                token=token,
                key=rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=AUTH0_ISSUER,    
            )
            return payload

        except jwt.JWTClaimsError:
            raise AuthError(
                {
                    'code': 'unauthorized',
                    'description': 'claims error check audience and issuer'
                }, 401
            )
            
        except jwt.ExpiredSignatureError:
            raise AuthError(
                {
                    'code': 'unauthorized',
                    'description': 'expired signature'
                }, 401
            )

        except Exception:
            raise AuthError(
                {
                    'code': 'invalid_header',
                    'description': 'can not parese the token'
                }, 400
            )
        
    raise AuthError(
        {
            'code': 'invalid_header',
            'description': 'can not find the appropriate key'
        }, 401
    )


'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator