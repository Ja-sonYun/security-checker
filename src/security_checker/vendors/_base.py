from abc import ABC, abstractproperty


class VendorBase(ABC):
    @abstractproperty
    def name(self) -> str: ...
