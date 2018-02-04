# SSL_connector
A simple wrapper of Windows socket 2 and OpenSSL for TLS connections.

Only using TCP connections and TLS v1.2.
Only PEM files are accepted for server keys and certificates.

##### References:
1. Server part: [https://wiki.openssl.org/index.php/Simple_TLS_Server](https://wiki.openssl.org/index.php/Simple_TLS_Server)
2. Client part: [https://stackoverflow.com/a/41321247/8688508](https://stackoverflow.com/a/41321247/8688508)

This is the first time I use C opaque pointer and visual studio unit test feature.
