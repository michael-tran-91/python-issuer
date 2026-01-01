import hashlib
from async_framework.validator import validate_model
from .validator_type import *

class AddPrivateKeyPemPayload(CommonModel):
    kid : str
    private_key_pem : str

def register_add_private_key_pem(sync_query, async_query):
    
    @async_query.register('issuer/add_private_key_pem')
    async def handle_add_private_key_pem(context, payload):

        mdl = AddPrivateKeyPemPayload.model_validate(payload)
        context["private_key_pem"][mdl.kid] = mdl.private_key_pem

        return {
            'status' : 'success'
        }
