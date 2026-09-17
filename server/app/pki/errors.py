class PkiError(Exception):
    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


class PkiValidationError(PkiError):
    pass


class PkiNotFoundError(PkiError):
    pass


class PkiConflictError(PkiError):
    pass


class PkiConfigurationError(PkiError):
    pass
