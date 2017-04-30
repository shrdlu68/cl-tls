;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-

(asdf:defsystem cl-tls
  :name "cl-tls"
  :version nil
  :author "Brian Kamotho"
  :license "BSD-3-Clause"
  :description "An implementation of the Transport Layer Security Protocols"

  :depends-on ("babel" "ironclad" "alexandria"
		       "cl-base64" "fast-io")
  :serial t
  :components ((:static-file "README")
	       (:static-file "LICENSE")
	       (:module "src"
		:components
			((:file "package")
			 (:file "utils")
			 (:module "ASN.1"
			  :components ((:file "asn.1")))
			 (:module "pkcs"
			  :components ((:file "pkcs1")
				       (:file "pkcs3")
				       (:file "pkcs5")
				       (:file "pkcs8")))
			 (:module "x509"
			  :serial t
			  :components ((:file "extensions")
				       (:file "x509")
				       (:file "ocsp")
				       (:file "validate")))
			 (:module "PEM"
			  :components ((:file "rfc7468")))
			 (:module "tls"
			  :components
				  ((:file "transport")
				   (:file "http")
				   (:file "ciphersuites")
				   (:file "alert")
				   (:file "crypto")
				   (:file "extensions")
				   (:file "tls")))))))
