import json
from base64 import b64encode
from uuid import uuid4

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.primitives import hashes

from iaplib.provider.common import InvalidDataError
from iaplib.provider.google import GooglePayment


class GoogleTestData(object):
    GAME_ID = 'net.vanyli.helios_payment'

    test_receipt = {
        "orderId": "12999763169054705758.1371079406387615",
        # <- I am making this up, orderId is not available in a testing transaction
        "packageName": "net.vanyli.helios_payment",
        "productId": "net.vanyli.helios_inapp_purchase",
        "purchaseTime": 1468358788591,
        "purchaseState": 0,
        "purchaseToken": "mfpnhdgkhakppcmgbmfgodic.AO-J1OwnmSTncqfRuvCjVoFtizua-hmnierz0Wz17aNNOViLuRAjlQ3TukYBnkF1zcYbj6iOTisLVWswjuwVRShb8TaWh8nQVCanei4gbgqtoOniG_nvQ44qEeHyk0DcntQIlK_Se4OPpdi7429Ara7u2V_s8B9faw",
    }
    signature = """egmwFs2IlHhY8LcedKuHb+ZskL3kgLzxge/amMvJZzyrHKB116/OW2s4YEZiOTpS7epivviyRCV5Elbcn6cddphM3zDmpmfl68KqBygURysr6oxntu5G1ngQ9vCgH46m8tcskax3lI5bfwLnWEA82CaXVKV+RinRVICwUmNwBHom52Z5OzM18pz8i05AUcdlRapfAFBXTbbgUiQlhwxTqhX/PlW3u2OXAWQcY1noyGbd73ESNwF04YBRoqypyB6bsGNPxwc5Fp2IPFr+aPHg0gQ8ff5eeTMHcUTdPG+g5QzOb4POxi0e7G0kNMnEvexzx1kLBFaCetT2tEqSkVvrXg=="""
    pub_key = """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgqXj064nTdIz4MYDt4tjb+fRn1GYyo+al9imD3+f6qKIzW8EaudK3jnlNkdpgFYiDzYROZGcQGJk6MU1IXdVmBkptOx8mwNNTOEUFZkvDa0hEYHoWWUaBX8RGE0rpxP8AYbIUOWf8tlKK8sulACw5mKYkR4xva0xND98Fc3vpTg0BcqQA1r+kh7UXD+sB4b5dEfZrNdHufnf0vxWkCiHMqkFp+EolEZjHtrLsTo62zHh4jneHSpZ9oTLO/0TBKIEaHNhmqQ7YQxkkOCcbHExB3Sj4tN89/83H04Vz3uAq9Bb9CtN3uXeysEVZQ/l2y6KI/shfRzfIF1Far8oUw1j7QIDAQAB"""
    raw_purchase_data = b"""{"packageName":"net.vanyli.helios_payment","productId":"net.vanyli.helios_inapp_purchase","purchaseTime":1468358788591,"purchaseState":0,"purchaseToken":"mfpnhdgkhakppcmgbmfgodic.AO-J1OwnmSTncqfRuvCjVoFtizua-hmnierz0Wz17aNNOViLuRAjlQ3TukYBnkF1zcYbj6iOTisLVWswjuwVRShb8TaWh8nQVCanei4gbgqtoOniG_nvQ44qEeHyk0DcntQIlK_Se4OPpdi7429Ara7u2V_s8B9faw"}"""
    game_id = 'net.vanyli.helios_payment'

    input_data = {
        'game_id': GAME_ID,
        'platform': GooglePayment.STORE_ID,
        'nonce': uuid4().hex,
        'receipt': {
            'payload': None,
            'signature': None,
        },
    }


class TestGoogle(GoogleTestData):

    @classmethod
    def setup_class(cls):
        cls.custom_signed_data = json.dumps(cls.test_receipt).encode('ascii')
        cls.custom_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=Backend())
        cls.custom_pub_key_bytes = b64encode(
            cls.custom_priv_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        )

        signer = cls.custom_priv_key.signer(PKCS1v15(), hashes.SHA1())
        signer.update(cls.custom_signed_data)
        cls.custom_signature = b64encode(signer.finalize())

        cls.input_data['receipt'] = {
            'payload': cls.custom_signed_data,
            'signature': cls.custom_signature,
        }

    def test_google_verify_signature_ok(self):
        processor = GooglePayment(self.custom_pub_key_bytes)
        result = processor.verify_signature(self.custom_signed_data, self.custom_signature)
        assert result is None

    def test_google_verify_signature_raise(self):
        processor = GooglePayment(self.custom_pub_key_bytes)
        with pytest.raises(InvalidSignature):
            processor.verify_signature(b64encode(json.dumps(self.test_receipt).encode('ascii')), self.custom_signature)

    def test_confirm_without_key_raises(self):
        processor = GooglePayment()
        with pytest.raises(InvalidDataError):
            processor.proceed(self.input_data)

    def test_real_data_signature(self):
        processor = GooglePayment()
        processor._set_key(self.pub_key)

        assert type(processor.public_key) == _RSAPublicKey

        processor.verify_signature(self.raw_purchase_data, self.signature)
