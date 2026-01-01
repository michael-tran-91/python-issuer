import hashlib
from async_framework.validator import validate_model
from .validator_type import *
import jwt

class VerifyPayload(CommonModel):
    token : str

    # check token format jwt
    @model_validator(mode='after')
    def check_token_format(cls, model):
        parts = model.token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token format. Expected JWT format with three parts separated by '.'")
        return model

def register_verify(sync_query, async_query):
    
    @async_query.register('issuer/verify')
    async def handle_verify(context, payload):

        vp = VerifyPayload.model_validate(payload)

        unverified_token = jwt.get_unverified_header(vp.token)
        kid = unverified_token.get('kid')
        alg = unverified_token.get('alg')

        if not alg:
            return {
                'status' : 'failed',
                'reason' : 'No alg found in token header'
            }
        if not kid:
            return {
                'status' : 'failed',
                'reason' : 'No kid found in token header'
            }
        
        jwk = context['jwk'].get(kid)
        if not jwk:
            return {
                'status' : 'failed',
                'reason' : 'JWK not found for given kid'
            }
        
        kty = jwk.get('kty')
        if kty == 'RSA':
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
        elif kty == 'EC':
            public_key = jwt.algorithms.ECAlgorithm.from_jwk(jwk)
        else:
            return {
                'status' : 'failed',
                'reason' : f'Unsupported key type: {kty}'
            }

        issuer_id = context.get('issuer_id')
        if not issuer_id:
            return {
                'status' : 'failed',
                'reason' : 'Issuer ID not found in context'
            }

        audience = context.get('audience')
        if not audience:
            return {
                'status' : 'failed',
                'reason' : 'Audience not found in context'
            }

        try:
            decoded = jwt.decode(
                vp.token,
                public_key,
                algorithms=[alg],
                issuer=issuer_id,
                audience=audience
            )
            return {
                'status' : 'success',
                'decoded' : decoded
            }
        except jwt.PyJWTError as e:
            return {
                'status' : 'failed',
                'reason' : f'Token verification failed: {str(e)}'
            }
        except Exception as e:
            return {
                'status' : 'failed',
                'reason' : f'Unexpected error during token verification: {str(e)}'
            }