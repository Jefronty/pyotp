import hashlib
from typing import Any, Optional

from . import utils
from .otp import OTP


class HOTP(OTP):
	"""
	Handler for HMAC-based OTP counters.
	"""
	def __init__(self, s, digits = 6, digest = hashlib.sha1, name = None,
				 issuer = None, initial_count = 0):
		"""
		:param s: secret in base32 format
		:param initial_count: starting HMAC counter value, defaults to 0
		:param digits: number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
		:param digest: digest function to use in the HMAC (expected to be sha1)
		:param name: account name
		:param issuer: issuer
		"""
		self.initial_count = initial_count
		super(HOTP, self).__init__(s=s, digits=digits, digest=digest, name=name, issuer=issuer)

	def at(self, count):
		"""
		Generates the OTP for the given count.

		:param count: the OTP HMAC counter
		:returns: OTP
		"""
		return self.generate_otp(self.initial_count + count)

	def verify(self, otp, counter):
		"""
		Verifies the OTP passed in against the current counter OTP.

		:param otp: the OTP to check against
		:param counter: the OTP HMAC counter
		"""
		return utils.strings_equal(str(otp), str(self.at(counter)))

	def provisioning_uri(
			self,
			name = None,
			initial_count = None,
			issuer_name = None,
			image = None):
		"""
		Returns the provisioning URI for the OTP.  This can then be
		encoded in a QR Code and used to provision an OTP app like
		Google Authenticator.

		See also:
			https://github.com/google/google-authenticator/wiki/Key-Uri-Format

		:param name: name of the user account
		:param initial_count: starting HMAC counter value, defaults to 0
		:param issuer_name: the name of the OTP issuer; this will be the
			organization title of the OTP entry in Authenticator
		:returns: provisioning URI
		"""
		return utils.build_uri(
			self.secret,
			name=name if name else self.name,
			initial_count=initial_count if initial_count else self.initial_count,
			issuer=issuer_name if issuer_name else self.issuer,
			algorithm=self.digest().name,
			digits=self.digits,
			image=image,
		)