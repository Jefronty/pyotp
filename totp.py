import calendar
import datetime
import hashlib
import time
from typing import Any, Union, Optional

from . import utils
from .otp import OTP


class TOTP(OTP):
	"""
	Handler for time-based OTP counters.
	"""
	def __init__(self, s, digits = 6, digest = hashlib.sha1, name = None,
				 issuer = None, interval = 30):
		"""
		:param s: secret in base32 format
		:param interval: the time interval in seconds for OTP. This defaults to 30.
		:param digits: number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
		:param digest: digest function to use in the HMAC (expected to be sha1)
		:param name: account name
		:param issuer: issuer
		"""
		self.interval = interval
		super(TOTP, self).__init__(s=s, digits=digits, digest=digest, name=name, issuer=issuer)

	def at(self, for_time, counter_offset = 0):
		"""
		Accepts either a Unix timestamp integer or a datetime object.

		To get the time until the next timecode change (seconds until the current OTP expires), use this instead::

			totp = pyotp.TOTP(...)
			time_remaining = totp.interval - datetime.datetime.now().timestamp() % totp.interval

		:param for_time: the time to generate an OTP for
		:param counter_offset: the amount of ticks to add to the time counter
		:returns: OTP value
		"""
		if not isinstance(for_time, datetime.datetime):
			for_time = datetime.datetime.fromtimestamp(int(for_time))
		return self.generate_otp(self.timecode(for_time) + counter_offset)

	def now(self):
		"""
		Generate the current time OTP

		:returns: OTP value
		"""
		return self.generate_otp(self.timecode(datetime.datetime.now()))

	def verify(self, otp, for_time = None, valid_window = 0):
		"""
		Verifies the OTP passed in against the current time OTP.

		:param otp: the OTP to check against
		:param for_time: Time to check OTP at (defaults to now)
		:param valid_window: extends the validity to this many counter ticks before and after the current one
		:returns: True if verification succeeded, False otherwise
		"""
		if for_time is None:
			for_time = datetime.datetime.now()

		if valid_window:
			for i in range(-valid_window, valid_window + 1):
				if utils.strings_equal(str(otp), str(self.at(for_time, i))):
					return True
			return False

		return utils.strings_equal(str(otp), str(self.at(for_time)))

	def provisioning_uri(self, name = None, issuer_name = None,
						 image = None):

		"""
		Returns the provisioning URI for the OTP.  This can then be
		encoded in a QR Code and used to provision an OTP app like
		Google Authenticator.

		See also:
			https://github.com/google/google-authenticator/wiki/Key-Uri-Format

		"""
		return utils.build_uri(self.secret, name if name else self.name,
							   issuer=issuer_name if issuer_name else self.issuer,
							   algorithm=self.digest().name,
							   digits=self.digits, period=self.interval, image=image)

	def timecode(self, for_time):
		"""
		Accepts either a timezone naive (`for_time.tzinfo is None`) or
		a timezone aware datetime as argument and returns the
		corresponding counter value (timecode).

		"""
		if for_time.tzinfo:
			return int(calendar.timegm(for_time.utctimetuple()) / self.interval)
		else:
			return int(time.mktime(for_time.timetuple()) / self.interval)
