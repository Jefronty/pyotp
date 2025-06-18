# pyotp
Python v2 compatible implementation of PyOTP

after installing [PyOTP](https://github.com/pyauth/pyotp) via PIP for python 2.7 there were several errors because it was no different than the version for Python 3.x
- type hinting in function/method definitions
- super() usage in child classes
- imports from urllib.parse

I edited each `.py` file in `/usr/local/lib/python2.7/dist-packages/pyotp/` and uploaded them here so that they are available for anyone else that also is using Python2
