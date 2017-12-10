"""Common exceptions"""


class ValueMismatch(Exception):
    def __call__(self, *args, **kwargs):
        ...
