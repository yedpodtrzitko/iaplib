import base64
import hashlib
import hmac
import json

from uuid import uuid4
from time import time

from iaplib.provider import FacebookPayment


class FacebookTestData(object):
    RECEIPT_DATA = {
        "request_id": uuid4().hex,
        "algorithm": "HMAC-SHA256",
        "amount": "5.00",
        "currency": "USD",
        "issued_at": int(time()),
        "payment_id": uuid4().hex,
        "quantity": "1",
        "status": "completed",
        'game_id': 'foo',
    }


class TestFacebook(FacebookTestData):
    @classmethod
    def setup_class(cls):
        cls.secret = b'13750c9911fec5865d01f3bd00bdf4db'

    def test_proceed(self):
        payload = self.RECEIPT_DATA
        payload['signed_request'] = self._generate_signed_request(self.RECEIPT_DATA)

        processor = FacebookPayment(self.secret)
        verified = processor.proceed(payload)
        assert verified['status'] == 'completed'

    def _generate_signed_request(self, data):
        signature = base64.urlsafe_b64encode(
            hmac.new(self.secret, msg=json.dumps(data).encode('ascii'), digestmod=hashlib.sha256).digest()
        )

        payload = base64.urlsafe_b64encode(json.dumps(data).encode('ascii'))
        return b"%s.%s" % (signature, payload)
