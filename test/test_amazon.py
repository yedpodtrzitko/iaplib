from copy import deepcopy

import pytest

from iaplib.provider.amazon import AmazonPayment
from iaplib.provider.common import InvalidDataError


class TestAmazon(object):
    def setup(self):
        self.developer_secret = '2:smXBjZkWCxDMSBvQ8HBGsUS1PK3jvVc8tuTjLNfPHfYAga6WaDzXJPoWpfemXaHg:iEzHzPjJ-XwRdZ4b4e7Hxw=='

        self.input_data = {
            'platform': AmazonPayment.STORE_ID,
            'game_id': 'net.vanyli.planet',
            'receipt': {
                'user_id': 'LRyD0FfW_3zeOlfJyxpVll-Z1rKn6dSf9xD3mUMSFg0=',
                'token': 'wE1EG1gsEZI9q9UnI5YoZ2OxeoVKPdR5bvPMqyKQq5Y=:1:11',
            },
        }

    def test_successful_verification(self):
        processor = AmazonPayment(secret=self.developer_secret)
        result = processor.proceed(self.input_data)
        assert result['productId'] == 'com.amazon.iapsamplev2.gold_medal'

    def test_invalid_verification(self):
        data = deepcopy(self.input_data)
        data['receipt']['user_id'] = data['receipt']['user_id'][:-2]
        processor = AmazonPayment(secret=self.developer_secret)
        with pytest.raises(InvalidDataError) as e:
            processor.proceed(data)
            assert str(e) == 'Invalid User ID'
