import requests

from .common import PaymentMixin, InvalidDataError


class AmazonPayment(PaymentMixin):
    STORE_ID = 'amazon'

    PAYMENT_STATE = STATE_PURCHASED = 0

    RETURN_STATE = {
        200: 'Success',
        400: 'The transaction represented by this Purchase Token is no longer valid.',
        496: 'Invalid sharedSecret',
        497: 'Invalid User ID',
        498: 'Invalid Purchase Token',
        499: 'The Purchase Token was created with credentials that have expired, use renew to generate a valid purchase token.',
        500: 'There was an Internal Server Error',
    }

    verify_url = "https://appstore-sdk.amazon.com/version/1.0/verifyReceiptId/developer/%(secret)s/user/%(user_id)s/receiptId/%(token)s"

    def __init__(self, secret=None):
        self.secret = secret

    def verify_signature(self, payload, signature):
        url_params = {
            'secret': self.secret,
            'user_id': payload,
            'token': signature,
        }

        target_url = self.verify_url % url_params
        response = requests.get(target_url)
        if response.status_code == 200:
            return response.json()

        raise InvalidDataError(self.RETURN_STATE.get(response.status_code, 'unknown error: %s' % response.status_code))

    def proceed(self, data):
        return self.verify_signature(data['receipt']['user_id'], data['receipt']['token'])
