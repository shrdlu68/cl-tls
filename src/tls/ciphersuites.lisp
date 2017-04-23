(in-package :cl-tls)

;; Block sizes
(defparameter +3des-block-size+ 8)
(defparameter +aes-block-size+ 16)

;; "The following definitions require that the server provide
;;   an RSA certificate that can be used for key exchange."
(defparameter +TLS_RSA_WITH_NULL_MD5+                  (fast-io:octets-from #(#x0 #x01)))
(defparameter +TLS_RSA_WITH_NULL_SHA+                  (fast-io:octets-from #(#x0 #x02)))
(defparameter +TLS_RSA_WITH_NULL_SHA256+               (fast-io:octets-from #(#x0 #x3B)))
(defparameter +TLS_RSA_WITH_RC4_128_MD5+               (fast-io:octets-from #(#x0 #x04)))
(defparameter +TLS_RSA_WITH_RC4_128_SHA+               (fast-io:octets-from #(#x0 #x05)))
(defparameter +TLS_RSA_WITH_3DES_EDE_CBC_SHA+          (fast-io:octets-from #(#x0 #x0A)))
(defparameter +TLS_RSA_WITH_AES_128_CBC_SHA+           (fast-io:octets-from #(#x0 #x2F)))
(defparameter +TLS_RSA_WITH_AES_256_CBC_SHA+           (fast-io:octets-from #(#x0 #x35)))
(defparameter +TLS_RSA_WITH_AES_128_CBC_SHA256+        (fast-io:octets-from #(#x0 #x3C)))
(defparameter +TLS_RSA_WITH_AES_256_CBC_SHA256+        (fast-io:octets-from #(#x0 #x3D)))
;; "The following cipher suite definitions are used for server-
;;   authenticated (and optionally client-authenticated) Diffie-Hellman."
(defparameter +TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA+       (fast-io:octets-from #(#x0 #x0D)))
(defparameter +TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA+       (fast-io:octets-from #(#x0 #x10)))
(defparameter +TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA+      (fast-io:octets-from #(#x0 #x13)))
(defparameter +TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA+      (fast-io:octets-from #(#x0 #x16)))
(defparameter +TLS_DH_DSS_WITH_AES_128_CBC_SHA+        (fast-io:octets-from #(#x0 #x30)))
(defparameter +TLS_DH_RSA_WITH_AES_128_CBC_SHA+        (fast-io:octets-from #(#x0 #x31)))
(defparameter +TLS_DHE_DSS_WITH_AES_128_CBC_SHA+       (fast-io:octets-from #(#x0 #x32)))
(defparameter +TLS_DHE_RSA_WITH_AES_128_CBC_SHA+       (fast-io:octets-from #(#x0 #x33)))
(defparameter +TLS_DH_DSS_WITH_AES_256_CBC_SHA+        (fast-io:octets-from #(#x0 #x36)))
(defparameter +TLS_DH_RSA_WITH_AES_256_CBC_SHA+        (fast-io:octets-from #(#x0 #x37)))
(defparameter +TLS_DHE_DSS_WITH_AES_256_CBC_SHA+       (fast-io:octets-from #(#x0 #x38)))
(defparameter +TLS_DHE_RSA_WITH_AES_256_CBC_SHA+       (fast-io:octets-from #(#x0 #x39)))
(defparameter +TLS_DH_DSS_WITH_AES_128_CBC_SHA256+     (fast-io:octets-from #(#x0 #x3E)))
(defparameter +TLS_DH_RSA_WITH_AES_128_CBC_SHA256+     (fast-io:octets-from #(#x0 #x3F)))
(defparameter +TLS_DHE_DSS_WITH_AES_128_CBC_SHA256+    (fast-io:octets-from #(#x0 #x40)))
(defparameter +TLS_DHE_RSA_WITH_AES_128_CBC_SHA256+    (fast-io:octets-from #(#x0 #x67)))
(defparameter +TLS_DH_DSS_WITH_AES_256_CBC_SHA256+     (fast-io:octets-from #(#x0 #x68)))
(defparameter +TLS_DH_RSA_WITH_AES_256_CBC_SHA256+     (fast-io:octets-from #(#x0 #x69)))
(defparameter +TLS_DHE_DSS_WITH_AES_256_CBC_SHA256+    (fast-io:octets-from #(#x0 #x6A)))
(defparameter +TLS_DHE_RSA_WITH_AES_256_CBC_SHA256+    (fast-io:octets-from #(#x0 #x6B)))
;; "The following cipher suites are used for completely anonymous
;;   Diffie-Hellman communications in which neither party is
;;   authenticated."
(defparameter +TLS_DH_anon_WITH_RC4_128_MD5+           (fast-io:octets-from #(#x0 #x18)))
(defparameter +TLS_DH_anon_WITH_3DES_EDE_CBC_SHA+      (fast-io:octets-from #(#x0 #x1B)))
(defparameter +TLS_DH_anon_WITH_AES_128_CBC_SHA+       (fast-io:octets-from #(#x0 #x34)))
(defparameter +TLS_DH_anon_WITH_AES_256_CBC_SHA+       (fast-io:octets-from #(#x0 #x3A)))
(defparameter +TLS_DH_anon_WITH_AES_128_CBC_SHA256+    (fast-io:octets-from #(#x0 #x6C)))
(defparameter +TLS_DH_anon_WITH_AES_256_CBC_SHA256+    (fast-io:octets-from #(#x0 #x6D)))

(defparameter +rsa-key-exchange-suites+
  (list +TLS_RSA_WITH_NULL_SHA+
	+TLS_RSA_WITH_NULL_SHA256+
	+TLS_RSA_WITH_RC4_128_MD5+
	+TLS_RSA_WITH_RC4_128_SHA+
	+TLS_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_RSA_WITH_AES_128_CBC_SHA+
	+TLS_RSA_WITH_AES_256_CBC_SHA+
	+TLS_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_RSA_WITH_AES_256_CBC_SHA256+))

(defparameter +dh-key-exchange-suites+
  (list +TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA256+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DH_anon_WITH_RC4_128_MD5+
	+TLS_DH_anon_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA256+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA256+))

(defparameter +dhe-key-exchange-suites+
  (list +TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA+
	+TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA256+))

(defparameter +rsa-authentication-suites+
  (list +TLS_RSA_WITH_NULL_MD5+
	+TLS_RSA_WITH_NULL_SHA+
	+TLS_RSA_WITH_NULL_SHA256+
	+TLS_RSA_WITH_RC4_128_MD5+
	+TLS_RSA_WITH_RC4_128_SHA+
	+TLS_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_RSA_WITH_AES_128_CBC_SHA+
	+TLS_RSA_WITH_AES_256_CBC_SHA+
	+TLS_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA256+))

(defparameter +dss-authentication-suites+
  (list +TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA+
	+TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA256+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA256+))

(defparameter +anon-authentication-suites+
  (list +TLS_DH_anon_WITH_RC4_128_MD5+
	+TLS_DH_anon_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA256+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA256+))

(defparameter +rc4-encryption-suites+
  (list +TLS_RSA_WITH_RC4_128_MD5+
	+TLS_RSA_WITH_RC4_128_SHA+
	+TLS_DH_anon_WITH_RC4_128_MD5+))

(defparameter +3des-encryption-suites+
  (list +TLS_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA+
	+TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_anon_WITH_3DES_EDE_CBC_SHA+))

(defparameter +aes-encryption-suites+
  (list +TLS_RSA_WITH_AES_128_CBC_SHA+
	+TLS_RSA_WITH_AES_256_CBC_SHA+
	+TLS_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA256+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA256+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA256+))

(defparameter +aes-128-ciphers+
  (list +TLS_RSA_WITH_AES_128_CBC_SHA+
	+TLS_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA256+))

(defparameter +aes-256-ciphers+
  (list +TLS_RSA_WITH_AES_256_CBC_SHA+
	+TLS_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA256+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA256+))

(defparameter +cbc-mode-ciphers+
  (list +TLS_RSA_WITH_AES_128_CBC_SHA+
	+TLS_RSA_WITH_AES_256_CBC_SHA+
	+TLS_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA256+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA256+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA256+
	+TLS_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA+
	+TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_anon_WITH_3DES_EDE_CBC_SHA+))

;; Mac, naming: <hash algorithm>
(defparameter +md5-ciphers+
  (list +TLS_RSA_WITH_NULL_MD5+
	+TLS_RSA_WITH_RC4_128_MD5+
	+TLS_DH_anon_WITH_RC4_128_MD5+))

(defparameter +sha1-ciphers+
  (list +TLS_RSA_WITH_NULL_SHA+
	+TLS_RSA_WITH_RC4_128_SHA+
	+TLS_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_RSA_WITH_AES_128_CBC_SHA+
	+TLS_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA+
	+TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_anon_WITH_3DES_EDE_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA+))

(defparameter +sha256-ciphers+
  (list +TLS_RSA_WITH_NULL_SHA256+
	+TLS_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DH_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DH_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_DSS_WITH_AES_128_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_128_CBC_SHA256+
	+TLS_DH_anon_WITH_AES_128_CBC_SHA256+
	+TLS_DH_DSS_WITH_AES_256_CBC_SHA256+
	+TLS_DH_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DHE_DSS_WITH_AES_256_CBC_SHA256+
	+TLS_DHE_RSA_WITH_AES_256_CBC_SHA256+
	+TLS_DH_anon_WITH_AES_256_CBC_SHA256+))
;; A summary of ECC in TLS:

;; ECDH ECDSA uses long-term ECDH keys and ECDSA-signed certificates.
;; More specifically, the server's certificate must contain a long-term ECDH pub-
;; lic key signed with ECDSA, and hence a SERVER KEY EXCHANGE message
;; need not be sent. The client generates an ECDH key pair on the same elliptic
;; curve as the server's long-term public key and may send its own public key in
;; the CLIENT KEY EXCHANGE message. Both client and server then perform an
;; ECDH key exchange and use the result as the premaster secret.

;; ECDHE ECDSA uses ephemeral ECDH keys and ECDSA-signed certifi-
;; cates. More specifically, the server's certificate must contain an ECDSA public
;; key signed with ECDSA. The server sends it ephemeral ECDH public key
;; and a specification of the corresponding elliptic curve in a SERVER KEY EX-
;; CHANGE message. The parameters are digitally signed with ECDSA using
;; the private key corresponding to the public key in the server's certificate. The
;; client generates another ECDH key pair on the same curve and sends its pub-
;; lic key to the server in a C LIENT K EY E XCHANGE message. Again, both the
;; client and the server perform an ECDH key exchange and use the result as the
;; premaster secret.

;; ECDH RSA uses long-term ECDH keys and RSA-signed certificates. This
;; key exchange algorithm is essentially the same as ECDH ECDSA, except that
;; the server's certificate is signed with RSA instead of ECDSA.

;; ECDHE RSA uses ephemeral ECDH keys and RSA-signed certificates. This
;; key exchange algorithm is essentially the same as ECDHE ECDSA, except
;; that the server's certificate must contain an RSA public key authorized for
;; signing, and the signature in the SERVER KEY EXCHANGE message must be
;; generated with the corresponding private RSA key. Also, the server certificate
;; must be signed with RSA instead of ECDSA.

;; ECDH anon uses an anonymous ECDH key exchange without any authenti-
;; cation. This basically means that no signature must be provided, and hence
;; no certificate must be in place. The ECDH public keys are exchanged in
;; SERVER KEY EXCHANGE and CLIENT KEY EXCHANGE messages.

(defparameter *supported-cipher-suites*
  (remove-if
   (lambda (arg) (member arg
			 (union +anon-authentication-suites+
				+rc4-encryption-suites+) :test #'equal))
   (append
    +rsa-key-exchange-suites+
    +dh-key-exchange-suites+
    +dhe-key-exchange-suites+
    +dss-authentication-suites+)))
