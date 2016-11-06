import re
import json

from base64 import b64decode
from struct import unpack, pack

import requests

from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.x509 import load_der_x509_certificate
from cryptography.exceptions import InvalidSignature

from OpenSSL import crypto
from OpenSSL.crypto import verify

from .common import PaymentMixin, InvalidDataError


class ApplePayment(PaymentMixin):
    STORE_ID = 'ios'

    PAYMENT_STATE = (STATE_PURCHASED, STATE_CANCELLED, STATE_REFUNDED) = (0, 1, 2)

    RETURN_STATE = {
        21000: 'The App Store could not read the JSON object you provided.',
        21002: 'The data in the receipt-data property was malformed.',
        21003: 'The receipt could not be authenticated.',
        21004: 'The shared secret you provided does not match the shared secret on file for your account.',
        21005: 'The receipt server is not currently available.',
        21006: 'This receipt is valid but the subscription has expired. When this status code is returned to your server, the receipt data is also decoded and returned as part of the response.',
        21007: 'This receipt is a sandbox receipt, but it was sent to the production service for verification.',
        21008: 'This receipt is a production receipt, but it was sent to the sandbox service for verification.',
    }

    def __init__(self, verify_url):
        self.verify_url = verify_url

    def proceed(self, data):
        """
        {
            'purchase_date_pst': '2016-11-06 09:57:12 Europe/London',
            'product_id': 'GoldPack',
            'original_transaction_id': '1000000012312312',
            'unique_identifier': 'abcdef01234567890abcdef01234567890abcdef',
            'original_purchase_date_pst': '2016-11-06 09:57:12 Europe/London',
            'original_purchase_date': '2016-11-06 09:57:12 Etc/GMT',
            'bvrs': '1.0',
            'original_purchase_date_ms': '1234567890123',
            'purchase_date': '2016-11-06 09:57:12 Etc/GMT',
            'item_id': '123456789',
            'purchase_date_ms': '1234567890123',
            'bid': 'net.vanyli.planet',
            'transaction_id': '1000000012312312',
            'quantity': '1',
        }
        """
        self.verify_signature(data['receipt']['payload'])

        r = requests.post(self.verify_url, data=json.dumps({'receipt-data': data['receipt']['payload']}))
        try:
            content = r.json()
        except ValueError:
            raise InvalidDataError('Unable to read response')

        try:
            status = int(content['status'])
        except (KeyError, ValueError):
            raise InvalidDataError('Unknown response format')

        if status in self.RETURN_STATE:
            raise InvalidDataError(self.RETURN_STATE[status])

        try:
            receipt = content['receipt']
        except KeyError:
            raise InvalidDataError('Receipt not found')

        return receipt

    def _disect_receipt(self, payload, encoded=True):
        """
        Signature format

        (big endian)
        +-----------------+-----------+------------------+-------------+
        | receipt version | signature | certificate size | certificate |
        +=================+===========+==================+=============+
        |          1 byte | 128 bytes |          4 bytes |       ->EOF |
        +-----------------+-----------+------------------+-------------+
        """
        pkcs7_der = b64decode(payload).decode('ascii') if encoded else payload
        signature_pattern = r'(?:"signature" = ")([^\"]+)";'
        info_pattern = '(?:"purchase-info" = ")([^\"]+)";'

        re_signature = re.search(signature_pattern, pkcs7_der, re.M)
        raw_signature = b64decode(re_signature.group(1))

        # TODO - get the first byte only
        receipt_version = unpack('>b', bytes(raw_signature[0:1]))[0]
        signature = unpack('128s', raw_signature[1:129])[0]
        cert_size = unpack('>I', raw_signature[129:133])[0]
        certificate_der = unpack('%ss' % cert_size, raw_signature[133:])[0]

        assert len(certificate_der) == cert_size
        assert len(signature) == 128
        assert receipt_version == 2

        # PKCS7 cert from PKCS7 DER blob
        # TODO - add more certificate checks (ie. issuer == 'Apple Inc.')
        certificate = load_der_x509_certificate(certificate_der, Backend())

        re_info = re.search(info_pattern, pkcs7_der, re.MULTILINE)
        raw_purchase_info = b64decode(re_info.group(1))
        # signed data is concatenated & packed `receipt version` + `purchase info`
        signed_data = pack("b%ss" % len(raw_purchase_info), receipt_version, raw_purchase_info)
        return certificate, signature, signed_data

    def verify_signature(self, payload):
        public_cert, signature, signed_data = self._disect_receipt(payload)
        try:
            verify(
                cert=public_cert,
                signature=signature,
                data=signed_data,
                digest='sha1',
            )
        except crypto.Error:
            raise InvalidSignature("invalid signature")
