In-App Purchase Verification Library
====================================

A library for a basic in-app payments verification


Example
-------

```python
from iaplib.provider import ApplePayment, InvalidDataError

processor = ApplePayment('https://buy.itunes.apple.com/verifyReceipt')
try:
    receipt_data = processor.proceed(apple_receipt)
except InvalidDataError:
    print('verification failed')
else:
    print('verification successful')
```


Supported vendors
-----------------

* Google Play

* AppStore

* Amazon

* Facebook
