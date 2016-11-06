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
