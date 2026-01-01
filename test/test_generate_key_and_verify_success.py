import unittest
from async_framework.async_query import AsyncQuery
from async_framework.sync_query import SyncQuery
from graph_issuer import register_graph_issuer_handlers
from datetime import datetime, timedelta, UTC
import jwt

class TestAsyncQuery(unittest.IsolatedAsyncioTestCase):
    async def test_generate_key_and_verify_failed_due_to_expired_date(self):
        async_query = AsyncQuery()
        sync_query = SyncQuery()
        register_graph_issuer_handlers(sync_query, async_query)

        context = {
            "jwk" : {},
            "private_key_pem" : {},
            "issuer_id" : "issuer",
            "audience" : "resolver"
        }
        # ------------------------------------------------------------------------------------
        # GENERATE_KEY
        #  - some applications can generate and store key
        # ------------------------------------------------------------------------------------
        res = await async_query.execute(context, "issuer/generate_key", {})
        self.assertEqual(res["status"], "success")

        # ------------------------------------------------------------------------------------
        # UPDATE KEYS
        #   - some applications can load jwk, private_keys
        # ------------------------------------------------------------------------------------
        # LOAD JWK
        await async_query.execute(context, "issuer/add_jwk", {
            "jwk": res["jwk"]
        })

        # LOAD PRIVATE KEY
        await async_query.execute(context, "issuer/add_private_key_pem", {
            "kid" : res["jwk"]["kid"],
            "private_key_pem" : res['private_key_pem']
        })

        # ------------------------------------------------------------------------------------
        # SIGN PAYLOAD WITH TARGET KID
        #   - some applications can sign a payload with loaded jwk, private_keys
        # ------------------------------------------------------------------------------------
        # INPUT PAYLOAD TO SIGN
        payload = {
            "sub": "root",
            "role": "root",
            "iss": context["issuer_id"],
            "aud": context["audience"],
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=10)
        }

        # INPUT KID
        kid = res['jwk']['kid']

        # FIND ALG, PRIVATE_KEY FROM KID
        alg = context["jwk"][kid]["alg"]
        private_key_pem = context["private_key_pem"][kid]

        # PREPARE HEADER TO SIGN
        headers = {"kid": kid, "alg": alg, "typ": "JWT"}

        # SIGN TO CREATE TOKEN
        token = jwt.encode(payload, private_key_pem, algorithm=alg, headers=headers)

        verify_res = await async_query.execute(context, "issuer/verify", {
            "token": token
        })
        self.assertEqual(verify_res["status"], "success")


if __name__ == "__main__":
    unittest.main()