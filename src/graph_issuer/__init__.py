from .verify import register_verify
from .add_jwk import register_add_jwk
from .generate_key import register_generate_key
from .add_private_key_pem import register_add_private_key_pem

def register_graph_issuer_handlers(sync_query, async_query):
    register_verify(sync_query, async_query)
    register_add_jwk(sync_query, async_query)
    register_generate_key(sync_query, async_query)
    register_add_private_key_pem(sync_query, async_query)