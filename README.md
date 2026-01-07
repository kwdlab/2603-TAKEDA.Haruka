# 2603-TAKEDA.Haruka
2026年3月卒業  竹田晴香

# Overview
This project provides internationalized implementations of the Apache htpasswd and htdigest utilities.
It enables proper handling of non-ASCII user IDs and passwords by supporting automatic character encoding conversion to Unicode, UTF-8 and NFC normalization.

# Description
The standard Apache htpasswd and htdigest commands internally treat user IDs and passwords as raw byte sequences and do not perform character encoding conversion or Unicode normalization.
As a result, authentication fails when non-ASCII characters such as Japanese, Korean, Chinese, or emoji are used.
By unifying all inputs into Unicode + UTF-8 + NFC before hash generation, this implementation ensures consistent and interoperable authentication behavior across different languages and environments.
Both HTTP Basic authentication and HTTP Digest authentication are supported through the tools ihtpasswd and ihtdigest.

# Requirements
C

# Author
Haruka Takeda

# Reference
Apache HTTP Server
https://httpd.apache.org/
RFC 7617: The 'Basic' HTTP Authentication Scheme
https://www.rfc-editor.org/rfc/rfc7617
RFC 7616: HTTP Digest Access Authentication
https://www.rfc-editor.org/rfc/rfc7616
iconv
https://www.gnu.org/software/libiconv/

# License
Apache License, Version 2.0
iconv (GNU libiconv), LGPL-2.1-or-later

