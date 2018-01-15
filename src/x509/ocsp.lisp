;; Implementation of https://tools.ietf.org/html/rfc6960
;; and https://tools.ietf.org/html/rfc2560
(in-package :cl-tls)

(define-condition ocsp-error (error)
  ((log :initarg :log
	:accessor log-info)))

(defparameter *id-ad-ocsp* '(1 3 6 1 5 5 7 48 1))

(defmacro ocsp-catch-asn-error (&body body)
  `(handler-case
       ,@body
     (asn.1-decoding-error (err)
       (error 'ocsp-error
	      :log (format nil "Encountered an ASN decoding error: ~A" (text err))))))

;; CertID          ::=     SEQUENCE {
;; 	hashAlgorithm       AlgorithmIdentifier,
;; 	issuerNameHash      OCTET STRING, -- Hash of issuer's DN
;; 	issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
;;         serialNumber        CertificateSerialNumber }
(defun create-cert-id (issuer-dn issuer-pub-key
		       cert-serial-number &optional (hash-algorithm :sha1))
  (let ((hash-oid (ecase hash-algorithm
		    (:md5 '(1 2 840 113549 2 5))
		    (:sha1 '(1 3 14 3 2 26))
		    (:sha224 '(2 16 840 1 101 3 4 2 4))
		    (:sha256 '(2 16 840 1 101 3 4 2 1))
		    (:sha384 '(2 16 840 1 101 3 4 2 2))
		    (:sha512 '(2 16 840 1 101 3 4 2 3))))
	(issuer-name-hash (ironclad:digest-sequence hash-algorithm issuer-dn))
	(issuer-key-hash (ironclad:digest-sequence hash-algorithm issuer-pub-key)))
    (create-asn-sequence (list (cat-vectors (asn-serialize hash-oid :oid)
					    (asn-serialize nil :null))
			       :sequence)
			 (list issuer-name-hash :octet-string)
			 (list issuer-key-hash :octet-string)
			 (list cert-serial-number :integer))))

;; Request         ::=     SEQUENCE {
;; reqCert                     CertID,
;;        singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
(defun create-request (cert-id #|&optional extension|#)
  (asn-serialize cert-id :sequence))

(defun create-tbs-request (identifiers)
  "identifiers is a list of lists with identifier-dn identifier-pub-key, and serial number"
  (setf identifiers (loop for identifier in identifiers collecting
							(apply #'create-cert-id identifier)))
  (let ((request-list (asn-serialize
		       (fast-io:with-fast-output (out)
			 (loop for cert-id in identifiers do
			   (fast-io:fast-write-sequence (create-request cert-id) out)))
		       :sequence)))
    (asn-serialize
     ;; This is commented out because some responders and parsers
     ;; don't recognize the optional version field.
     ;; So we send without a version field.
     ;; (fast-io:with-fast-output (out)
     ;;   (fast-io:fast-write-sequence (create-explicit-tag (asn-serialize 0 :integer)
     ;; 							 0)
     ;; 				    out)
     ;;   (fast-io:fast-write-sequence request-list out))
     request-list
     :sequence)))

(defun prepare-ocsp-request (identifiers)
  ;; No signature for now
  (asn-serialize (create-tbs-request identifiers) :sequence))

(defun verify-ocsp-signature (signing-certificate response-data
			      signature signature-algorithm)
  (let* ((tbs (tbs-certificate signing-certificate))
	 (pki (subject-pki tbs))
	 (pk-algorithm (car (getf pki :algorithm-identifier)))
	 (pk (getf pki :subject-public-key)))
    (multiple-value-bind (signature-alg hash-alg)
	(parse-signature-algorithm signature-algorithm)
      (unless (eql signature-alg pk-algorithm)
	(return-from verify-ocsp-signature nil))
      (let* ((verification-digest (ironclad:digest-sequence hash-alg
							    response-data)))
	(case signature-alg
	  (:rsa
	   (let ((pub-key (ironclad:make-public-key :rsa
						    :n (getf pk :modulus)
						    :e (getf pk :public-exponent))))
	     (setf signature (rsa-encrypt signature pub-key))
	     (unless (= (aref signature 1) 1)
	       (return-from verify-ocsp-signature nil))
	     (setf signature (subseq signature (1+ (position 0 signature :start 1))))
	     (multiple-value-bind (asn-type digest-info) (ocsp-catch-asn-error
							  (parse-der signature))
	       (unless (and (eql asn-type :sequence)
			    (= (length digest-info) 2))
		 (return-from verify-ocsp-signature nil))
	       (destructuring-bind (digest-algorithm digest) digest-info
		 (declare (ignorable digest-algorithm))
		 (unless (eql (first digest) :octet-string)
		   (return-from verify-ocsp-signature nil))
		 (setf digest (second digest))
		 (timing-independent-compare verification-digest digest)))))
	  (:dsa
	   (let ((pub-key
		   (ironclad:make-public-key :dsa
					     :p (getf pk :dsa-p)
					     :q (getf pk :dsa-q)
					     :g (getf pk :dsa-g)
					     :y (getf pk :dsa-public-key))))
	     (multiple-value-bind (asn-type dss-sig-value) (ocsp-catch-asn-error
							    (parse-der signature))
	       (unless (and (eql asn-type :sequence)
			    (= (length dss-sig-value) 2))
		 (return-from verify-ocsp-signature nil))
	       (unless (every (lambda (arg)
				(asn-type-matches-p :integer arg)) dss-sig-value))
	       (destructuring-bind (r s) dss-sig-value
		 (setf signature (ironclad:make-signature :dsa :r (second r) :s (second s)))
		 (ironclad:verify-signature pub-key verification-digest signature))))))))))

(defun parse-response-data (data serial)
  (flet ((fail ()
	   (error 'ocsp-error :log "Invalid responseData")))
    (setf data (ocsp-catch-asn-error (asn-sequence-to-list data)))
    (unless (<= 3 (length data) 5) (fail))
    (macrolet ((bind-responses (ll &body body)
		 `(cond ((= 3 (length ,ll))
			 (destructuring-bind
			     (responder-id produced-at responses
			      &optional (version 1) response-extensions)
			     ,ll
			   ,@body))
			((= 4 (length ,ll))
			 (if (= (first (first ,ll)) 0)
			     (destructuring-bind
				 (version responder-id produced-at responses
				  &optional response-extensions)
				 ,ll
			       ,@body)
			     (destructuring-bind
				 (responder-id produced-at responses response-extensions
				  &optional (version 1))
				 ,ll
			       ,@body)))
			(t
			 (destructuring-bind
			     (version responder-id produced-at
			      responses response-extensions)
			     ,ll
			   ,@body))))
	       (bind-single-response (ll &body body)
		 `(cond ((= 3 (length ,ll))
			 (destructuring-bind
			     (cert-id cert-status this-update
			      &optional next-update single-extensions)
			     ,ll
			   ,@body))
			((= 4 (length ,ll))
			 (if (eql (first (fourth ,ll)) 0)
			     (destructuring-bind
				 (cert-id cert-status this-update
				  next-update &optional single-extensions)
				 ,ll
			       ,@body)
			     (destructuring-bind
				 (cert-id cert-status this-update
				  single-extensions &optional next-update)
				 ,ll
			       ,@body)))
			((= 5 (length ,ll))
			 (destructuring-bind
			     (cert-id cert-status this-update
			      next-update single-extensions)
			     ,ll
			   ,@body))
			(t (fail)))))
      (bind-responses
       data
       (declare (ignorable version responder-id response-extensions))
       (unless (asn-type-matches-p :sequence responses) (fail))
       (let ((single-response (first (second responses))))
	 (unless (asn-type-matches-p :sequence single-response) (fail))
	 (setf single-response (second single-response))
	 (bind-single-response
	  single-response
	  (unless (asn-type-matches-p :sequence cert-id) (fail))
	  (setf cert-id (second cert-id))
	  (unless (eql serial (second (fourth cert-id)))
	    (error 'ocsp-error
		   :log
		   "Serial does not match that of the requested certificate"))
	  ;; TODO: Perhaps cache ocsp responses?
	  (unless (asn-type-matches-p :generalized-time this-update)
	    (fail))
	  (setf this-update (asn-time-to-universal-time (second this-update)))
	  ;; Ensure the response was signed sufficiently recently (12 hours)
	  (setf produced-at (asn-time-to-universal-time (second produced-at)))
	  (unless (< (- (get-universal-time) produced-at) (* 12 60 60)))
	  ;; Check that thisUpdate is in the past
	  (unless (<= this-update (get-universal-time))
	    (error 'ocsp-error :log "OCSP thisUpdate is in the future"))
	  ;; Verify that next-update is greater than the current time.
	  (when next-update
	    (unless (eql (first next-update) 0) (fail))
	    (setf next-update (multiple-value-list (ocsp-catch-asn-error
						    (parse-der (second next-update)))))
	    (unless (asn-type-matches-p :generalized-time next-update)
	      (fail))
	    (setf next-update (asn-time-to-universal-time (second next-update)))
	    (unless (> next-update (get-universal-time))
	      (error 'ocsp-error :log "OCSP NextUpdate is in the past")))
	  ;; (format t "~&Single extensions: ~S~%" single-extensions)
	  (case (first cert-status)
	    (0 :good)
	    (1 :revoked)
	    (2 :unknown)
	    (otherwise (error 'ocsp-error :log "Invalid certificate status.")))))))))

(defun check-ocsp (subject issuer)
  "Return the status of the certificate or signal an error"
  (with-slots ((raw-subject raw) (subject-tbs tbs-certificate)) subject
    (with-slots ((raw-issuer raw)) issuer
      (let* ((ocsp-location (getf
			     (authority-information-access (extensions subject-tbs))
			     :ocsp))
	     (url (cdr ocsp-location))
	     (issuer-dn-octets (get-issuer-octets raw-subject))
	     (issuer-pubkey-octets (get-pubkey-octets raw-issuer))
	     (serial (serial subject-tbs))
	     (ocsp-request (prepare-ocsp-request (list (list issuer-dn-octets
							     issuer-pubkey-octets
							     serial))))
	     (ocsp-response
	       (handler-case
		   (http-request url
				 :method :post
				 :content-type "application/ocsp-request"
				 :body ocsp-request)
		 (http-error (err)
		   (error 'ocsp-error :log (format nil "A HTTP error occured while sending an OCSP request. Details: ~A" (log-info err)))))))
	;; (format t "~&Checking OCSP from url [~S]~%" url)
	(flet ((fail () (error 'ocsp-error :log "Malformed response")))
	  (setf ocsp-response (multiple-value-list (ocsp-catch-asn-error
						    (parse-der ocsp-response))))
	  (unless (asn-type-matches-p :sequence ocsp-response)
	    (fail))
	  (setf ocsp-response (second ocsp-response))
	  (unless (<= 1 (length ocsp-response) 2) (fail))
	  (destructuring-bind (response-status &optional response-bytes)
	      ocsp-response
	    (unless (asn-type-matches-p :enumerated response-status)
	      (fail))
	    (when response-bytes
	      (unless (= 0 (first response-bytes))
		(fail))
	      (setf response-bytes (multiple-value-list
				    (ocsp-catch-asn-error (parse-der (second response-bytes)))))
	      (unless (asn-type-matches-p :sequence response-bytes)
		(fail))
	      (setf response-bytes (second response-bytes)))
	    (case (second response-status)
	      (0;;Successful
	       (or response-bytes
		   (error 'ocsp-error :log "No responseBytes received"))
	       (unless (= 2 (length response-bytes))
		 (fail))
	       (destructuring-bind (response-type response) response-bytes
		 (unless (and (asn-type-matches-p :oid response-type)
			      (asn-type-matches-p :octet-string response))
		   (fail))
		 (unless (equal (second response-type)
				(append *id-ad-ocsp* '(1)))
		   (error 'ocsp-error :log "Unknown OCSP response type"))
		 (setf response
		       (multiple-value-list
			(ocsp-catch-asn-error (parse-der (second response) :mode :serialized))))
		 (unless (asn-type-matches-p :sequence response)
		   (fail))
		 (setf response (ocsp-catch-asn-error (asn-sequence-to-list (second response)
									    :mode :serialized)))
		 (unless (<= 3 (length response) 4) (fail))
		 (destructuring-bind (response-data signature-algorithm
				      signature &optional certs) response
		   (setf signature-algorithm
			 (ocsp-catch-asn-error
			  (asn-sequence-to-list (second signature-algorithm))))
		   (unless (and (asn-type-matches-p :sequence response-data)
				(asn-type-matches-p :bit-string signature))
		     (fail))
		   (setf response-data (second response-data))
		   (setf signature (subseq (second signature) 1))
		   (cond (certs
			  ;; CA has designated OCSP signing.
			  ;; The certificate that signed the response
			  ;; is in certs
			  (unless (= (first certs) 0) (fail))
			  (setf certs (ocsp-catch-asn-error
				       (asn-sequence-to-list (second certs)
							     :mode :serialized)))
			  (let* ((signer (x509-decode (second (first certs))))
				 (extended-ku (extended-key-usage
					       (extensions (tbs-certificate signer)))))
			    ;; Ensure the OCSP-sign key-usage bit is set
			    (unless (member :ocsp-signing extended-ku)
			      (error 'ocsp-error
				     :log
				     "OCSP-sign bit is not set in signer's certificate"))
			    ;; Verify time validity
			    (unless (time-valid-p signer)
			      (error 'ocsp-error
				     :log "OCSP signer's certificate is out of date"))
			    ;; Verify signature
			    (unless (verify-signature signer issuer)
			      (error 'ocsp-error
				     :log "OCSP signer's certificate is not issued by CA"))
			    ;; Check the ocsp signature
			    (unless (verify-ocsp-signature
				     signer
				     (asn-serialize response-data :sequence)
				     signature signature-algorithm)
			      (error 'ocsp-error :log "Bad OCSP signature"))))
			 (t
			  ;; The CA (issuer) is the OCSP signer
			  (unless (verify-ocsp-signature
				   issuer
				   (asn-serialize response-data :sequence)
				   signature signature-algorithm)
			    (error 'ocsp-error :log "Bad OCSP signature"))))
		   (parse-response-data response-data serial))))
	      (1;;malformedRequest
	       (error 'ocsp-error :log "Response status: malformedRequest"))
	      (2;;internalError
	       (error 'ocsp-error :log "Response status: InternalError"))
	      (3;;tryLater
	       (error 'ocsp-error :log "Response status: tryLater"))
	      (5;;sigRequired
	       (error 'ocsp-error :log "Response status: sigRequired"))
	      (6;;unauthorized
	       (error 'ocsp-error :log "Response status: unauthorized"))
	      (otherwise
	       (error 'ocsp-error :log "Unknown reponse status")))))))))
