import abc


class InvalidDataError(ValueError):
    pass


class PaymentMixin:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def verify_signature(self, payload, signature):
        pass

    @abc.abstractmethod
    def proceed(self, *args, **kwargs):
        pass

    @abc.abstractproperty
    def STORE_ID(self):
        pass


def get_vendor(provider_id):
    from .google import GooglePayment
    from .amazon import AmazonPayment
    from .apple import ApplePayment

    providers = {
        GooglePayment.STORE_ID: GooglePayment,
        AmazonPayment.STORE_ID: AmazonPayment,
        ApplePayment.STORE_ID: ApplePayment,
    }
    try:
        return providers[provider_id]
    except KeyError:
        raise InvalidDataError("unknown vendor supplied")
