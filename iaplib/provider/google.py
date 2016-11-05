import base64
import json

from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import load_der_public_key

from .common import PaymentMixin, InvalidDataError


class GooglePayment(PaymentMixin):
    public_key = None

    STORE_ID = 'gp'

    PAYMENT_STATE = (STATE_PURCHASED, STATE_CANCELLED, STATE_REFUNDED) = (0, 1, 2)

    def __init__(self, key=None):
        if key:
            self._set_key(key)

    def _set_key(self, public_key):
        # Key from Google Play is a X.509 subjectPublicKeyInfo DER SEQUENCE.
        self.public_key = load_der_public_key(base64.b64decode(public_key), Backend())

    def verify_signature(self, payload, signature):
        if not self.public_key:
            raise InvalidDataError("verification key not initialized")
        verifier = self.public_key.verifier(base64.b64decode(signature), PKCS1v15(), SHA1())
        verifier.update(payload)
        verifier.verify()

    def proceed(self, data):
        self.verify_signature(data['receipt']['payload'], data['receipt']['signature'])

        receipt = json.loads(data['receipt']['payload'])
        if not all([x in receipt for x in ("orderId", "productId", "purchaseToken", "purchaseState")]):
            raise InvalidDataError("incomplete receipt data")

        if receipt['purchaseState'] != self.STATE_PURCHASED:
            raise InvalidDataError("unexpected purchase state")

        return receipt
