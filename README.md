CL-TLS is a prototype Common Lisp implementation 
of TLS and related protocols and standards including:
   -RFC5246
   -ASN.1
   -x{501,509}
   -PKCS 1,3,5,8

TLS is the IETF-standardized successor of Netscape's SSL
protocol. Sometimes TLS/SSL are used interchangeably.
At this point, there is no intention to support the
older versions of the protocols (SSLv3 and below)

The project is currently in its early development
phase and should only be used for experimental
purposes.

CL-TLS uses Ironclad as its cryptographic 
back-end (at the time of writing, the ironclad in quicklisp
has not yet been updated to the new maintained repo,
use sharplispers/ironclad).
See the system definition file for other dependencies

The project started as an attempt to create a 
network-based TLS fuzzer, but soon
morphed of its own volition into a full-fledged 
TLS implementation.

Extensive testing, fuzzing, and code review is needed.
Style guidelines, optimizations, feature-completion 
patches, bug fixes, and other contributions are 
welcome.

For an overview of known attacks against TLS and other
issues relevant to implementors and users, see
https://tools.ietf.org/html/rfc7457
At a minimum, CL-TLS will follow the recommendations
and considerations in the aforementioned document before
a proper alpha release is announced.

I also intend to fully document the internals of CL-TLS.

So far:
   -You can initiate sessions and exchange data through a TLS tunnel
   either as a server or a client, for RSA, DSA, and Diffie-Hellman 
   cipher suites. There is no support for ECDSA suites yet.
   -Certificate path validation works for 
   certificates signed using RSA or DSA. As above, no support 
   for ECDSA signature verification yet.
   -Support for PEM-encoded certificate chains.
   -Support for most features of the TLS 1.2 spec such as
    fragmentation and session renegotiation.

Major TODOs before alpha release:
  -Finalizing work on hello extensions.
  -Fuzzing.
  -Speed/Memory optimizations.

Features that would be nice, but are not essential
  -Support for initializing with multiple certificates
  -ECDSA/ECDH/ECDHE support
  -Session resumption support
  -Support for post-RFC5246 cipher suites
  -rfc{4346,2246,6520}
  -pkcs#{7,12}
  -DTLS
  -Tools for the generation and management of public/private keys and
  certificates
  -DANE

CL-TLS does not offer gray streams, threading, sockets, event-loop, or
compression functionality. This limits the code of CL-TLS to simply opening
and managing a TLS tunnel through an octet stream and enhances portability
and extensibility. However, libraries that offer this functionality
(such as threaded or evented servers), can be built trivially
on top of CL-TLS.
See https://github.com/shrdlu68/secure-sockets as an example.

Here is an example of a simple text echo server that
implements a simple one-thread-per-request model using usocket
and bordeaux-threads:

```
(require :cl-tls)

(ql:quickload :bordeaux-threads)
(ql:quickload :usockets)
(ql:quickload :babel)

(defun echo-server (port &optional (host "localhost"))
  (let ((sock (usocket:socket-listen host port
				     :reuse-address t
				     :element-type '(unsigned-byte 8))))
    (cl-tls:initialize-listener
     :certificate "/path/to/cert.pem"
     :private-key "/path/to/key.pem")
    (loop
      for thread-id upfrom 0
      for new-sock = (usocket:socket-accept sock)
      for session-stream = (usocket:socket-stream new-sock)
      for handler = (multiple-value-bind (reader writer)
			(cl-tls:accept-tunnel :io-stream session-stream)
		      (lambda ()
			(loop
			  with id = thread-id
			  for in = (funcall reader)
			  for line = (and in
					  (babel:octets-to-string in))
			  if line do
			    (format t "~&~:R thread received data: ~A~%"
				    id line)
			    (funcall writer in)
			  else do
			    (format t
				    "~&Peer closed tunnel, ~:R thread exiting~%" id)
			    (return nil))))
      do
	 (bordeaux-threads:make-thread handler))))
```

And here is an example using client functionality:

```
(require :cl-tls)
(ql:quickload :babel)

(defun client-test (port &optional (host "localhost"))
  (let* ((sock (usocket:socket-connect
		host port
		:protocol :stream
		:element-type '(unsigned-byte 8))))
    (multiple-value-bind (reader writer close-callback)
	(cl-tls:request-tunnel
	 :certificate "/path/to/cert.pem"
	 :private-key "/path/to/key.pem"
	 :io-stream (usocket:socket-stream sock)
	 :peer-ip-addresses '((127 0 0 1))
	 :ca-certificates "/path/to/CA/ca-cert.pem")
      (loop
	for out = (read-line *standard-input* nil nil)
	for line = (and out
			(babel:string-to-octets out))
	if line do
	  (funcall writer line)
	  (let ((in (funcall reader)))
	    (cond (in
		   (format t "~&Received data: ~A~%"
			   (babel:octets-to-string in)))
		  (t
		   (funcall close-callback)
		   (return nil))))
	else do
	  (format t "~&Closing tunnel...~%")
	  (funcall close-callback)
	  (return nil)))))
```

Preliminary API documentation:

request-tunnel (&key certificate private-key ca-certificates
	       	     io-stream input-stream output-stream
		     include-ciphers exclude-ciphers
		     peer-dns-name peer-ip-addresses)

		Attempts to request a TLS tunnel from a server
		through an octet stream
		
		:io-stream A duplex octet stream
		
		:input-stream In the case where separate input and output
			      streams are used, an octet input stream
			      
		:output-stream An octet output stream

		:private-key A (DER/PEM-encoded) private key
			     (currently only DSA, RSA and DH private keys are supported)
			     If the private key is encrypted, you will be prompted for
			     the passphrase
			     
		:certificate A file containing a PEM-encoded list of one
			     or more cerificates
			     The file should consist of one or more
			     ----- BEGIN CERTIFICATE -----
			     ----- END CERTIFICATE -----
			     blocks. White space and other information around these blocks
			     is permitted and will be ignored. Support for PKCS#12-encoded
			     certificate chains is not yet implemented.
		:ca-certificates Either: 1. A directory to look for .crt, .pem, and .der
				 	    CA certificates in
					 2. A PEM-encoded file containing CA certificates,
					    encoded as explained above.
				 For servers, these are only needed if the server
				 needs to authenticate clients, i.e the clients are
				 expected to have client certificates issued to them.
				 This is not used very widely in practice.
				 For clients, CA certificates are used to authenticate
				 servers.
				 TLS clients such as browsers typically use a collection
				 of root certificates that are included by some means of
				 vetting, either provided by the operating system or
				 by the creators/maintainers of the browser.
				 You can use the CAs that your OS/browser has vetted,
				 or you can select which CAs to trust by yourself.
				 For example, most GNU/Linux systems have a package that
				 provides vetted root certificates, typically found in
				 the file "/etc/ssl/certs/ca-certificates.crt"
				 See also: https://curl.haxx.se/docs/sslcerts.html
				 
				 If you want to or have issued your own certificates,
				 include your CA certificate here, either in
				 addition to other CA certificates or as the sole
				 CA certificates. The client and server will only
				 be able to validate remote endpoints whose certificates
				 are signed by a CA certificate that is included,
				 there is no way to "accept" unvalidated certificates.

		
		:include-ciphers A list of symbols of cipher suites to add to the
				 default cipher list.
				 The symbols denote one of the cryptographic characteristics
				 of a cipher suite: key exchange, authentication
				 bulk encryption, mac, digest algorithms, prf, and key sizes.
				 Currently supported options:
				 :rsa-ke (RSA key exchange)
				 :rsa-auth (RSA authentication)
				 :dh (static dh) :dhe (ephemeral dh)
				 :dsa :anon (no authentication-vulnerable to MITM attacks!)
				 :rc4 (broken and prohibited) :3des
				 :aes128 :aes256 :cbc (cipher block chaining mode)
				 :md5 :sha1 :sha256
				 
		:exclude-ciphers A list of symbols of cipher suites to exclude
				 from the default cipher list.
				 :anon and :rc4 are already excluded by default
				 
		:peer-dns-name DNS-name of the peer. This is checked against
			       the dns-name values in the subject alternative name extension
			       of the certificate presented by the peer.
			       It is also used in the SNI extension, which is important
			       for virtual servers to determine which server the client
			       wants to contact.
		
		:peer-ip-addresses List of IP addresses of the peer
				   This is checked against the ip-address values
				   in the subject alternative name extension
			       	   of the certificate presented by the peer.

initialize-listener (&key certificate private-key ca-certificates
				include-ciphers exclude-ciphers force-reinitialize
				authenticate-client-p require-authentication-p
				dh-params)
			
		Loads resources needed for a server session and
		sets configuration options
		Servers need to call this once when initializing.
						 
		:authenticate-client-p When true, an attempt to authenticate the client
				       will be made. However, the client may send back an
				       empty certificate if it does not have
				       (an appropriate) certificate. This option defaults
				       to nil
				       
		:require-authentication-p When true, the server will be asked for a
					  certificate, and the connection will
					  fail if the client fails to provide a certificate.
					  This option defaults to nil.

accept-tunnel (&key io-stream input-stream output-stream)
	      => read-callback,write-callback,close-callback

	      Attempts to accept a client's request for a
	      TLS tunnel through an octet stream

		read-callback A closure whose argument list is in the form
			      (&key (eof-error-p nil) (eof-value nil))
			      that returns the contents
			      of one TLS record (2^14 bytes or less).
			      If :eof-error-p is true, the condition cl:end-of-file
			      will be signaled if the TLS tunnel is closed properly
			      (i.e a close_notify alert is received)
			      If :eof-error-p is false, eof-value is returned rather
			      than isgnalling end-of-file.
			      If an error is encountered while attempting to read from
			      the underlying stream (for example is a socket connection
			      is terminated without properly closing the TLS tunnel),
			      the condition cl:stream-error will be signalled.
		write-callback A closure of one argument, an octet vector of arbitrary size,
			       to be sent down the tunnel
			       Attempting to write to a closed TLS tunnel will
			       signal the condition cl:stream-error
			       If an error is encountered while attempting to write to
			       the underlying stream (for example is a socket connection
			       is terminated without properly closing the TLS tunnel),
			       the condition cl:stream-error will be signalled.
		close-callback A closure of no arguments that politely closes the TLS
			       connection by sending a close_notify alert.

(defclass address ()
  ((host :initarg :host
	 :accessor host)
   (port :initarg :port
	 :accessor port)))

request-stream-to-address (address)
		 =>octet stream
	Specialize this generic function and provide socket functionality.
	This is needed by some of the functionality in cl-tls that may need
	to open sockets, such as contacting OCSP responders.
	For example, to if you are using usockets:
	(defmethod cl-tls:request-stream-to-address ((addr cl-tls:address))
	  (usocket:socket-stream (usocket:socket-connect
	  (cl-tls:host addr) (cl-tls:port addr)
	  :protocol :stream
	  :element-type '(unsigned-byte 8))))

This API will likely change as development continues.
