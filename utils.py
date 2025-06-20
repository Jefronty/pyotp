import unicodedata
from hmac import compare_digest
from typing import Dict, Optional, Union

from urllib import quote, urlencode
from urlparse import urlparse


def build_uri(secret, name, initial_count = None, issuer = None,
			  algorithm = None, digits = None, period = None,
			  image = None):
	"""
	Returns the provisioning URI for the OTP; works for either TOTP or HOTP.

	This can then be encoded in a QR Code and used to provision the Google
	Authenticator app.

	For module-internal use.

	See also:
		https://github.com/google/google-authenticator/wiki/Key-Uri-Format

	:param secret: the hotp/totp secret used to generate the URI
	:param name: name of the account
	:param initial_count: starting counter value, defaults to None.
		If none, the OTP type will be assumed as TOTP.
	:param issuer: the name of the OTP issuer; this will be the
		organization title of the OTP entry in Authenticator
	:param algorithm: the algorithm used in the OTP generation.
	:param digits: the length of the OTP generated code.
	:param period: the number of seconds the OTP generator is set to
		expire every code.
	:param image: optional logo image url
	:returns: provisioning uri
	"""
	# initial_count may be 0 as a valid param
	is_initial_count_present = (initial_count is not None)

	# Handling values different from defaults
	is_algorithm_set = (algorithm is not None and algorithm != 'sha1')
	is_digits_set = (digits is not None and digits != 6)
	is_period_set = (period is not None and period != 30)

	otp_type = 'hotp' if is_initial_count_present else 'totp'
	base_uri = 'otpauth://{0}/{1}?{2}'

	url_args = {'secret': secret}  # type: Dict[str, Union[None, int, str]]

	label = quote(name)
	if issuer is not None:
		label = quote(issuer) + ':' + label
		url_args['issuer'] = issuer

	if is_initial_count_present:
		url_args['counter'] = initial_count
	if is_algorithm_set:
		url_args['algorithm'] = algorithm.upper()  # type: ignore
	if is_digits_set:
		url_args['digits'] = digits
	if is_period_set:
		url_args['period'] = period
	if image:
		image_uri = urlparse(image)
		if image_uri.scheme != 'https' or not image_uri.netloc or not image_uri.path:
			raise ValueError('{} is not a valid url'.format(image_uri))
		url_args['image'] = image

	uri = base_uri.format(otp_type, label, urlencode(url_args).replace("+", "%20"))
	return uri


def strings_equal(s1, s2):
	"""
	Timing-attack resistant string comparison.

	Normal comparison using == will short-circuit on the first mismatching
	character. This avoids that by scanning the whole string, though we
	still reveal to a timing attack whether the strings are the same
	length.
	"""
	s1 = unicodedata.normalize('NFKC', u'%s' % s1)
	s2 = unicodedata.normalize('NFKC', u'%s' % s2)
	return compare_digest(s1.encode("utf-8"), s2.encode("utf-8"))
