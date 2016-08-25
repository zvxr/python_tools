
from collections import namedtuple

"""This is more for organization.
Encoder namedtuples include two functions: one for encoding data and another for decoding.
"""

Encoder = namedtuple('Encoder', ('encode', 'decode'))
