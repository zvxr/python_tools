
import base64

from base import Encoder


Base64Encoder = Encoder('Base64Encoder', base64.b64encode, base64.b64decode)
URLSafeBase64Encoder = Encoder('URLSafeBase64Encoder', base64.urlsafe_b64encode, base64.urlsafe_b64decode)
