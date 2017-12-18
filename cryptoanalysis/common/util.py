"""Common utilities"""

import cryptoanalysis.common.exception as exc


def match(matchee, matcher):
    """
    :param matchee: Item to be matched
    :param matcher: Item that matches given item
    :raises: exception.ValueMismatch
    """

    if matchee != matcher:
        exc_msg = "'{matcher}' does not match '{matchee}'".format(
            matcher=matcher,
            matchee=matchee
        )
        raise exc.ValueMismatch(exc_msg)

    return 0

