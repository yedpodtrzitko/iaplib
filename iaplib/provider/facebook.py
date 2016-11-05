import base64
import hashlib
import hmac
import json
import time

from uuid import uuid4

from .common import PaymentMixin, InvalidDataError


class FacebookPayment(PaymentMixin):
    STORE_ID = 'fb'

    PAYMENT_STATE = (STATE_INITIATED, STATE_COMPLETED, STATE_FAILED) = (0, 1, 2)

    def __init__(self, app_secret, app_id=None):
        self.app_secret = app_secret
        self.app_id = app_id

    def proceed(self, data):
        signature, payload = data['signed_request'].split(b'.', 1)
        return self.verify_signature(payload, signature)

    def verify_signature(self, payload, signature):
        decoded_payload = FacebookPayment.base64_url_decode(payload)
        expected_sig = hmac.new(self.app_secret, msg=decoded_payload, digestmod=hashlib.sha256).digest()

        data = json.loads(self.base64_url_decode(payload).decode('ascii'))
        # allow the signed_request to function for upto 1 day
        raw_signature = self.base64_url_decode(signature)
        if raw_signature == expected_sig and data['issued_at'] > (time.time() - 86400):
            return data

        raise InvalidDataError()

    @classmethod
    def base64_url_decode(cls, data):
        assert type(data) is bytes
        data = data
        data += b'=' * (4 - (len(data) % 4))
        return base64.urlsafe_b64decode(data)

    def init(self, data, context):
        transaction_id = "%s%s" % (int(time.time()), uuid4().hex)
        return {
            'request_id': transaction_id,
        }
