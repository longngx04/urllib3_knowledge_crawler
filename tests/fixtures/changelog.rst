Changes
=======

2.7.0 (2025-07-16)
-------------------

- Fixed SSRF vulnerability when following redirects (CVE-2025-43802, GHSA-vqfr-h8mv-ghfj)
- Fixed connection pooling race condition (#3456)
- Added HTTP/2 support for HTTPS connections
- Deprecated ``HTTPResponse.getheaders()`` in favor of ``HTTPResponse.headers``
- Updated API documentation for retry module

2.6.0 (2025-05-01)
-------------------

- Bugfix: Handle socket timeout correctly on Windows (#3400)
- Added retry configuration via ``Retry`` class
- New: Connection recycling for long-lived pools

2.5.0 (2025-03-15)
-------------------

- Fixed TLS certificate validation edge case
- Deprecated legacy ``request_encode_body`` API
- Documentation: Improved migration guide from v1 to v2

2.4.0 (2025-01-10)
-------------------

- Security: Fixed header injection vulnerability (CVE-2025-12345)
- Bugfix: Correct chunked transfer encoding handling
- Added proxy authentication support
