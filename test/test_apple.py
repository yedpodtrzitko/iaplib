from base64 import b64encode

import pytest
from OpenSSL.crypto import load_certificate, FILETYPE_PEM, load_privatekey, PKey, TYPE_RSA, X509
from cryptography.exceptions import InvalidSignature

from iaplib.provider.apple import ApplePayment
from test.apple_data import AppleTestData


class TestApple(AppleTestData):
    SANDBOX_VERIFICATION_URL = 'https://sandbox.itunes.apple.com/verifyReceipt'
    
    @classmethod
    def setup_class(cls):
        cls.intermediate_cert = load_certificate(FILETYPE_PEM, cls.intermediate_certificate_pem)
        cls.pub_cert = load_certificate(FILETYPE_PEM, cls.apple_root_cert_pem)
        cls.priv_key = load_privatekey(FILETYPE_PEM, cls._root_key_pem)

        cls.priv_key_spoof = PKey()
        cls.priv_key_spoof.generate_key(TYPE_RSA, 1024)

        cls.pub_cert_spoof = X509()
        cls.pub_cert_spoof.set_pubkey(cls.priv_key_spoof)

    def test_signed_data_ok(self):
        processor = ApplePayment(self.SANDBOX_VERIFICATION_URL)
        processor.verify_signature(self.RAW_RECEIPT_DATA)

    def test_signed_data_invalid_cert_raises(self):
        def mock_disect(payload, encoded=True):
            certificate, signature, signed_data = orig_disect(payload, encoded)
            return self.pub_cert, signature, signed_data

        processor = ApplePayment(self.SANDBOX_VERIFICATION_URL)
        with pytest.raises(InvalidSignature):
            orig_disect = processor._disect_receipt
            processor._disect_receipt = mock_disect
            processor.verify_signature(self.RAW_RECEIPT_DATA)

    def test_invalid_signature_raises(self):
        processor = ApplePayment(self.SANDBOX_VERIFICATION_URL)

        test_data = self.input_data
        test_data['receipt']['payload'] = b64encode(
            (self.RECEIPT_DATA % dict(signature=self.invalid_signature)).encode('ascii')
        )

        with pytest.raises(InvalidSignature):
            processor.proceed(test_data)

    def test_valid_receipt(self):
        processor = ApplePayment(self.SANDBOX_VERIFICATION_URL)

        test_data = self.input_data
        test_data['receipt']['payload'] = b64encode(
            (self.RECEIPT_DATA % dict(signature=self.signature)).encode('ascii')
        ).decode('ascii')

        res = processor.proceed(test_data)
        assert res['transaction_id'].endswith('64')
