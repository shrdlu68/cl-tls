(defpackage :cl-tls
  (:use :cl :alexandria)
  (:nicknames :tls)
  (:documentation "CL-TLS is a Common Lisp implemetation of TLS and related specifications"))

(in-package :cl-tls)

(export '(;; TLS
	  request-tunnel initialize-listener accept-tunnel
	  tls-stream-error tls-error tunnel-closed
	  
	  ;; ASN.1
	  parse-der asn-sequence-to-list encode-oid asn-serialize
	  create-asn-sequence

	  ;; X509
	  x509-decode

	  ;; PKCS1
	  rsa-encrypt rsa-decrypt rsassa-pkcs1.5-sign
	  rsassa-pkcs1.5-verify

	  ;; PKCS5
	  pbes2-decrypt

	  ;; Transport
	  address host port request-stream-to-address))
