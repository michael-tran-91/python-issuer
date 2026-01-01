import hashlib
from async_framework.validator import validate_model
from .validator_type import *

class JWKInfo(CommonModel):
    kid : str
    kty : str
    use : str
    alg : str
    n : str
    e : str

class AddJWKPayload(CommonModel):
    jwk : JWKInfo

def register_add_jwk(sync_query, async_query):
    
    @async_query.register('issuer/add_jwk')
    async def handle_add_jwk(context, payload):

        ajp = AddJWKPayload.model_validate(payload)
        context['jwk'][ajp.jwk.kid] = ajp.jwk.model_dump()

        return {
            'status' : 'success'
        }
