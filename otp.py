import base64
import hashlib
import hmac
from typing import Any, Optional


class OTP(object):
	"""
	Base class for OTP handlers.
	"""
	def __init__(self, s, digits = 6, digest = hashlib.sha1, name = None,
				 issuer = None):
		self.digits = digits
		self.digest = digest
		self.secret = s
		self.name = name or 'Secret'
		self.issuer = issuer

	def generate_otp(self, input):
		"""
		:param input: the HMAC counter value to use as the OTP input.
			Usually either the counter, or the computed integer based on the Unix timestamp
		"""
		if input < 0:
			raise ValueError('input must be positive integer')
		hasher = hmac.new(self.byte_secret(), self.int_to_bytestring(input), self.digest)
		hmac_hash = bytearray(hasher.digest())
		offset = hmac_hash[-1] & 0xf
		code = ((hmac_hash[offset] & 0x7f) << 24 |
				(hmac_hash[offset + 1] & 0xff) << 16 |
				(hmac_hash[offset + 2] & 0xff) << 8 |
				(hmac_hash[offset + 3] & 0xff))
		str_code = str(code % 10 ** self.digits)
		while len(str_code) < self.digits:
			str_code = '0' + str_code

		return str_code

	def byte_secret(self):
		secret = self.secret
		missing_padding = len(secret) % 8
		if missing_padding != 0:
			secret += '=' * (8 - missing_padding)
		return base64.b32decode(secret, casefold=True)

	@staticmethod
	def int_to_bytestring(i, padding = 8):
		"""
		Turns an integer to the OATH specified
		bytestring, which is fed to the HMAC
		along with the secret
		"""
		result = bytearray()
		while i != 0:
			result.append(i & 0xFF)
			i >>= 8
		# It's necessary to convert the final result from bytearray to bytes
		# because the hmac functions in python 2.6 and 3.3 don't work with
		# bytearray
		return bytes(bytearray(reversed(result)).rjust(padding, b'\0'))
