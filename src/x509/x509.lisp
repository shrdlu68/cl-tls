;; x509 parsing
;; Spec: https://tools.ietf.org/html/rfc5280
(in-package :cl-tls)

(defconstant +md2WithRSAEncryption+ #X02)
(defconstant +md5WithRSAEncryption+ #X04)
(defconstant +sha1WithRSAEncryption+ #X05)
(defconstant +sha224WithRSAEncryption+ #X0e)
(defconstant +sha256WithRSAEncryption+ #X0b)
(defconstant +sha384WithRSAEncryption+ #X0c)
(defconstant +sha512WithRSAEncryption+ #X0d)

;; https://tools.ietf.org/html/rfc5280
;; Certificate ::= SEQUENCE {
;; 	tbsCertificate          TBSCertificate,
;; 	signatureAlgorithm      AlgorithmIdentifier,
;; 	signature               BIT STRING
;; 	}

;; TBSCertificate ::= SEQUENCE {
;; 	version          [ 0 ]  Version DEFAULT v1(0),
;; 	serialNumber            CertificateSerialNumber,
;; 	signature               AlgorithmIdentifier,
;; 	issuer                  Name,
;; 	validity                Validity,
;; 	subject                 Name,
;; 	subjectPublicKeyInfo    SubjectPublicKeyInfo,
;; 	issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
;; 	subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
;; 	extensions        [ 3 ] Extensions OPTIONAL
;; 	}

(define-condition x509-decoding-error (error)
  ((text :initarg :text :reader text)))

;; (defclass algorithm-identifier ()
;;   ((algorithm :initarg :algorithm
;; 	      :accessor algorithm)
;;    (parameters :initarg :parameters
;; 	       :initform nil
;; 	       :accessor parameters)))

(defclass x509-extension ()
  ((subject-alternative-name :initform nil
			     :accessor subject-alternative-name)
   (issuer-alternative-name :initform nil
			    :accessor issuer-alternative-name)
   (authority-key-identifier :initform nil
			     :accessor authority-key-identifier)
   (subject-key-identifier :initform nil
			   :accessor subject-key-identifier)
   (key-usage :initform nil
	      :accessor key-usage)
   (certificate-policies :initform nil
			 :accessor certificate-policies)
   (policy-mappings :initform nil
		    :accessor policy-mappings)
   (basic-constraints :initform nil
		      :accessor basic-constraints)
   (extended-key-usage :initform nil
		       :accessor extended-key-usage)
   (crl-distribution-points :initform nil
			    :accessor crl-distribution-points)
   (authority-information-access :initform nil
				 :accessor authority-information-access)
   (subject-information-access :initform nil
			       :accessor subject-information-access)))
   
(defclass tbs-certificate ()
  ((version :initarg :version
	    :initform 0
	    :accessor version)
   (serial :initarg :serial
	   :accessor serial)
   (signature :initarg :signature
	      :accessor signature)
   (issuer :initarg :issuer
	   :accessor issuer)
   (validity :initarg :validity
	     :accessor validity
	     :type validity)
   (subject :initarg :subject
	    :accessor subject)
   (subject-pki :initarg :subject-pki
			    :initform nil
			    :accessor subject-pki
			    :type algorithm-identifier)
   (issuer-unique-id :initarg :issuer-unique-id
		     :initform nil
		     :accessor issuer-unique-id)
   (subject-unique-id :initarg subject-unique-id
		      :initform nil
		      :accessor subject-unique-id)
   (extensions :initarg :extensions
	       :initform nil
	       :accessor extensions)))

(defclass x509v3-certificate ()
  ((raw :initarg :raw
	:accessor raw
	:documentation "The raw octets of the certificate")
   (hash :initarg :hash
	 :accessor hash
	 :documentation "The hash of the raw octets of the certificate")
   (tbs-certificate :initarg :tbs-certificate
		    :accessor tbs-certificate)
   (signature-algorithm :initarg :signature-algorithm
			:accessor signature-algorithm)
   (signature :initarg :signature
	      :accessor signature)))

(defmethod print-object ((cert x509v3-certificate) stream)
  (with-slots (raw tbs-certificate signature-algorithm) cert
    (with-slots (serial issuer validity subject subject-pki) tbs-certificate
      (let ((*print-pretty* t))
	(format stream "~&Certificate info: ~%")
	(format stream "Length: ~A~%" (length raw))
	(format stream "Signature algorithm: ~A~%" signature-algorithm)
	(format stream "Serial number: ~A~%" serial)
	(format stream "Issuer: ~A~%" issuer)
	(format stream "Validity: Between ~A and ~A~%"
		(getf validity :not-before)
		(getf validity :not-after))
	(format stream "Subject: ~A~%" subject)
	(format stream "Public key algorithm: ~A~%"
		(car (getf subject-pki :algorithm-identifier)))))))

(defun parse-directory-name (rdns)
  "Parse DER-encoded distinguishedName sequence"
  (let (dn)
    (loop
      for rdn in rdns
      do
	 (multiple-value-bind (element-type ava) (parse-der (second rdn))
	   (flet ((fail ()
		    (error 'x509-decoding-error
			   :text "Invalid encoding of DirectoryName")))
	     (unless (eql element-type :sequence) (fail))
	     (let (attribute-type)
	       (unless (= 2 (length ava)) (fail))
	       (setf attribute-type (second (first ava)))
	       (unless (find (first (second ava))
			     '(:ia5-string :printable-string :telex-string
			       :universal-string :utf8-string :bmp-string))
		 (fail))
	       (when (and (= 4 (length attribute-type))
			  (equal '(2 5 4) (subseq attribute-type 0 3)))
		 (case (fourth attribute-type)
		   (6
		    (unless (= (length (second (second ava))) 2) (fail))
		    (setf (getf dn :country-name)
			  (second (second ava))))
		   (10
		    (unless (<= 1 (length (second (second ava))) 200) (fail))
		    (setf (getf dn :organization)
			  (second (second ava))))
		   (11
		    (unless (<= 1 (length (second (second ava))) 200) (fail))
		    (setf (getf dn :organizational-unit-name)
			  (second (second ava))))
		   (3
		    (unless (<= 1 (length (second (second ava))) 200) (fail))
		    (setf (getf dn :common-name)
			  (second (second ava))))
		   (7
		    (unless (<= 1 (length (second (second ava))) 200) (fail))
		    (setf (getf dn :locality-name)
			  (second (second ava))))
		   (8
		    (unless (<= 1 (length (second (second ava))) 200) (fail))
		    (setf (getf dn :state-or-province-name)
			  (second (second ava))))))))))
    dn))

(defun parse-pka (public-key-algorithm)
  "Parse the OID in the SubjectPublicKeyInfo and the parameters"
  (let (pka algorithm params)
    (unless (and (= 2 (length public-key-algorithm))
		 (eql (first (first public-key-algorithm)) :oid))
      (error 'x509-decoding-error :text "Length or type mismatch in SubjectPublicKeyInfo AlgorithmIdentifier field"))
    (setf pka (second (first public-key-algorithm)))
    (cond
      ;; RSA
      ((equal '(1 2 840 113549 1 1 1) pka)
       (setf algorithm :rsa))
      ;; DSA
      ((equal '(1 2 840 10040 4 1) pka)
       (setf algorithm :dsa)
       (unless (eql (first (second public-key-algorithm)) :sequence)
	 (error 'x509-decoding-error :text "Dss-Params should be an ASN.1 sequence."))
       (let ((dss-params (second (second public-key-algorithm))))
	 (unless (and (= (length dss-params) 3)
		      (every #'(lambda (li) (eql (first li) :integer)) dss-params))
	   (error "Invalid Dss-params"))
	 (setf (getf params :dsa-p) (second (first dss-params)))
	 (setf (getf params :dsa-q) (second (second dss-params)))
	 (setf (getf params :dsa-g) (second (third dss-params)))))
      ;; DH
      ((equal '(1 2 840 113549 1 3 1) pka)
       (setf algorithm :dh)
       (unless (eql :sequence (first (second public-key-algorithm)))
	 (error :text "DH parameters should be a sequence"))
       (let ((dh-params (second (second public-key-algorithm))))
	 (unless (and (< 1 (length dh-params) 4)
		      (every #'(lambda (li) (eql (first li) :integer)) dh-params))
	   (error 'x509-decoding-error
		  :text "Invalid DHParameter field in SubjectPublicKeyInfo"))
	 (setf (getf params :dh-P) (second (first dh-params)))
	 (setf (getf params :dh-G) (second (second dh-params)))
	 (when (= (length dh-params) 3)
	   (setf (getf params :dh-privateValueLength) (second (third dh-params))))))
      ;; ECDSA
      ((equal '(1 2 840 10045 2 1) pka)
       (setf algorithm :ecdsa)
       ;; ECParameters ::= CHOICE {
       ;; namedCurve         OBJECT IDENTIFIER
       ;; -- implicitCurve   NULL
       ;; -- specifiedCurve  SpecifiedECDomain
       ;;      }
       (unless (or (eql (first (second public-key-algorithm)) :null)
		   (eql (first (second public-key-algorithm)) :oid))
	 (error 'x509-decoding-error
		:text "ECParameters for id-ecPublicKey should be either NULL or OID"))
       (let ((named-curve (second (second public-key-algorithm))))
	 (setf (getf params :named-curve)
	       (cond
		 ((equal named-curve '(1 2 840 10045 3 1 1)) :secp192r1)
		 ((equal named-curve '(1 2 840 10045 3 1 7)) :secp256r1)
		 ((equal named-curve '(1 3 132 0 1)) :sect163k1)
		 ((equal named-curve '(1 3 132 0 15)) :sect163r2)
		 ((equal named-curve '(1 3 132 0 16)) :sect283k1)
		 ((equal named-curve '(1 3 132 0 17)) :sect283r1)
		 ((equal named-curve '(1 3 132 0 26)) :sect233k1)
		 ((equal named-curve '(1 3 132 0 27)) :sect233r1)
		 ((equal named-curve '(1 3 132 0 33)) :secp224r1)
		 ((equal named-curve '(1 3 132 0 34)) :secp384r1)
		 ((equal named-curve '(1 3 132 0 35)) :secp521r1)
		 ((equal named-curve '(1 3 132 0 36)) :sect409k1)
		 ((equal named-curve '(1 3 132 0 37)) :sect409r1)
		 ((equal named-curve '(1 3 132 0 38)) :sect571k1)
		 ((equal named-curve '(1 3 132 0 39)) :sect571r1)
		 (t
		  (error 'x509-decoding-error
			 :text "Unknown or unsupported EC named curve"))))))
      ((equal '(1 3 132 1 12) pka)
       (setf algorithm :ecdh))
      (t
       (error 'x509-decoding-error
	      :text "Unrecognized or unsupported public key algorithm")))
    (cons algorithm params)))

(defun parse-pub-key (ov algorithm)
  (let (pub-key)
    (case algorithm
      ;; RSAPublicKey ::= SEQUENCE { modulus INTEGER, -- n publicExponent INTEGER -- e }
      (:rsa
       (let ((rsa-public-key (multiple-value-list
			      (parse-der ov :start 1))))
	 (unless (eql (first rsa-public-key) :sequence)
	   (error 'x509-decoding-error :text "The subjectPublicKeyInfo bit string should contain an ASN.1 sequence"))
	 (setf rsa-public-key (second rsa-public-key))
	 (loop for element in rsa-public-key do
	   (unless (eql (first element) :integer)
	     (error 'x509-decoding-error :text "Expected integers in PKI field.")))
	 (setf (getf pub-key :modulus) (second (first rsa-public-key)))
	 (setf (getf pub-key :public-exponent) (second (second rsa-public-key)))))
      ;; DSA
      (:dsa
       (let ((dsa-public-key (multiple-value-list
			      (parse-der ov :start 1))))
	 (unless (eql (first dsa-public-key) :integer)
	   (error 'x509-decoding-error :text "Expected a DSA public key; DSAPublicKey ::= INTEGER -- public key, Y"))
	 (setf (getf pub-key :dsa-public-key) (second dsa-public-key))))
      ;; DH
      (:dh
       (let ((dh-public-value (multiple-value-list
			       (parse-der ov :start 1))))
	 (unless (eql (first dh-public-value) :integer)
	   (error 'x509-decoding-error :text "Invalid encoding of subjectPublicKeyInfo"))
	 (setf (getf pub-key :dh-Y) (second dh-public-value)))))
    pub-key))

(defun parse-signature-algorithm (sig)
  "Parse the sequence containing OID + optional parameters"
  (destructuring-bind (oid &optional parameters) sig
    (declare (ignorable parameters))
    (unless (eql :oid (first oid))
      (error 'x509-decoding-error :text "Error decoding signatureAlgorithm"))
    (setf oid (second oid))
    (cond
      ;; RSA 
      ((and (= (length oid) 7)
	    (equal (butlast oid) '(1 2 840 113549 1 1)))
       (values :rsa
	       (case (seventh oid)
		 (2 :md2)
		 (4 :md5)
		 (5 :sha1)
		 (11 :sha256)
		 (12 :sha384)
		 (13 :sha512)
		 (otherwise
		  (error 'x509-decoding-error :text "Unknown digest algorithm")))))
      ;; DSA with sha1
      ((equal oid '(1 2 840 10040 4 3))
       (values :dsa :sha1))
      ;; DSA with SHA-224
      ((equal oid '(2 16 840 1 101 3 4 3 1))
       (values :dsa :sha224))
      ;; DSA with SHA-256
      ((equal oid '(2 16 840 1 101 3 4 3 2))
       (values :dsa :sha256))
      ;; ECDSA with sha1
      ((equal oid '(1 2 840 10045 4 1))
       (values :ecdsa :sha1))
      ;; ECDSA with sha256
      ((equal oid '(1 2 840 10045 4 2))
       (values :ecdsa :sha256))
      ;; ECDSA with sha1
      ((equal oid '(1 2 840 10045 4 3 1))
       (values :ecdsa :sha1))
      ;; ECDSA with sha256
      ((equal oid '(1 2 840 10045 4 3 2))
       (values :ecdsa :sha384))
      ;; ECDSA with sha384
      ((equal oid '(1 2 840 10045 4 3 3))
       (values :ecdsa :sha384))
      ;; ECDSA with sha512
      ((equal oid '(1 2 840 10045 4 3 4))
       (values :ecdsa :sha384))
      (t
       (error 'x509-decoding-error
	      :text
	      (format nil "Unknown or unsupported SignatureAlgorithm. OID: ~A" oid))))))

(defun process-extensions (extensions)
  (let ((extension-bag (make-instance 'x509-extension)))
    (unless (eql 3 (first extensions))
      (error 'x509-decoding-error :text "Extensions field should have explicit tag #3"))
    (setf extensions (multiple-value-list (parse-der (second extensions))))
    (unless (eql :sequence (first extensions))
      (error 'x509-decoding-error :text "Extensions field must be an ASN.1 sequence"))
    (setf extensions (second extensions))
    (unless (every (lambda (arg) (eql (first arg) :sequence)) extensions)
      (error 'x509-decoding-error :text "Extensions should be DER sequences"))
    (setf extensions
	  (loop for ext in extensions collecting (second ext)))
    (unless (every (lambda (arg)
		     (or
		      (and (= 3 (length arg))
			   (eql (first (first arg)) :oid)
			   (eql (first (second arg)) :boolean)
			   (eql (first (third arg)) :octet-string))
		      (and (= 2 (length arg))
			   (eql (first (first arg)) :oid)
			   (eql (first (second arg)) :octet-string))))
		   extensions)
      (error 'x509-decoding-error :text "Error parsing extensions"))
    (setf extensions (loop
		       for ext in extensions
		       collecting
		       (if (= (length ext) 2)
			   (destructuring-bind (extension-id extension-value) ext
			     (list (second extension-id)
				   nil
				   (second extension-value)))
			   (destructuring-bind (extension-id critical-p extension-value) ext
			     (list (second extension-id)
				   (second critical-p)
				   (second extension-value))))))
    (loop
      for ext in extensions do
	(destructuring-bind (extension-id critical-p extension-value) ext
	  (cond
	    ((equal extension-id '(2 5 29 35))
	     (process-extension extension-bag critical-p
				extension-value :authority-key-identifier))
	    ((equal extension-id '(2 5 29 14))
	     (process-extension extension-bag critical-p
				extension-value :subject-key-identifier))
	    ((equal extension-id '(2 5 29 15))
	     (process-extension extension-bag critical-p
				extension-value :key-usage))
	    ((equal extension-id '(2 5 29 32))
	     (process-extension extension-bag critical-p
				extension-value :certificate-policies))
	    ((equal extension-id '(2 5 29 33))
	     (process-extension extension-bag critical-p
				extension-value :policy-mappings))
	    ((equal extension-id '(2 5 29 17))
	     (process-extension extension-bag critical-p
				extension-value :subject-alternative-name))
	    ((equal extension-id '(2 5 29 18))
	     (process-extension extension-bag critical-p
				extension-value :issuer-alternative-name))
	    ((equal extension-id '(2 5 29 19))
	     (process-extension extension-bag critical-p
				extension-value :basic-constraints))
	    ((equal extension-id '(2 5 29 30))
	     (process-extension extension-bag critical-p
				extension-value :name-constraints))
	    ((equal extension-id '(2 5 29 36))
	     (process-extension extension-bag critical-p
				extension-value :policy-constraints))
	    ((equal extension-id '(2 5 29 37))
	     (process-extension extension-bag critical-p
				extension-value :extended-key-usage))
	    ((equal extension-id '(2 5 29 31))
	     (process-extension extension-bag critical-p
				extension-value :crl-distribution-points))
	    ((equal extension-id '(2 5 29 54))
	     (process-extension extension-bag critical-p
				extension-value :inhibit-anypolicy))
	    ((equal extension-id '(2 5 29 46))
	     (process-extension extension-bag critical-p
				extension-value :freshest-crl))
	    ((equal extension-id '(1 3 6 1 5 5 7 1 1))
	     (process-extension extension-bag critical-p extension-value
				:authority-information-access))
	    ((equal extension-id '(1 3 6 1 5 5 7 1 11))
	     (process-extension extension-bag critical-p
				extension-value :subject-information-access))
	    (t
	     (when critical-p ;the extension is unknown and critical
	       (error 'extension-bag-decoding-error
		      :text "Encountered unknown critical extension"))))))
    extension-bag))

(defmacro bind-tbs (tbs &body body)
  `(if (eql (first (first ,tbs)) 0)
       (destructuring-bind (version serial certificate-signature-algorithm
			    issuer validity subject subject-public-key-info
			    &optional extensions) ,tbs
	 ,@body)
       (destructuring-bind (serial certificate-signature-algorithm
			    issuer validity subject subject-public-key-info
			    &optional extensions version) ,tbs
	 ,@body)))

(defun parse-tbs-certificate (tbs-certificate)
  ;; Remove obsolete UniqueIdentifier fields if present, we're not interested in them
  (setf tbs-certificate
	(remove-if (lambda (el) (if (eql (first el) :bit-string) t)) tbs-certificate))
  (unless (<= 6 (length tbs-certificate) 8)
    (error 'x509-decoding-error
	   :text "There must be 6|7|8 elements in tbs-certificate"))
  (bind-tbs
   tbs-certificate
   (make-instance
    'tbs-certificate
    :version
    (cond (version
	   (unless (eql (first version) 0)
	     (error 'x509-decoding-error
		    :text "Version field should be explicitly tagged with type=0"))
	   (let ((v (multiple-value-list (parse-der (second version)))))
	     (unless (eql (first v) :integer)
	       (error 'x509-decoding-error
		      :text "Version field should be an ASN.1 integer"))
	     (unless (<= 1 (second v) 2)
	       (error 'x509-decoding-error :text "Version must be 2 or 3"))
	     (1- (second v))))
	  (t
	   1))
    :serial
    (progn 
      (unless (eql (first serial) :integer)
	(error 'x509-decoding-error :text "Serial field should be an ASN.1 integer"))
      (second serial))
    :signature
    (progn (unless (eql (first certificate-signature-algorithm) :sequence)
	     (error 'x509-decoding-error
		    :text "Signature algorithm field should be an ASN.1 sequence"))
	   (multiple-value-bind (signature-algorithm digest-algorithm)
	       (parse-signature-algorithm (second certificate-signature-algorithm))
	     ;; (unless (and (eql (car (signature-algorithm x509)) signature-algorithm)
	     ;; 		  (eql (cdr (signature-algorithm x509)) digest-algorithm))
	     ;;   (error 'x509-decoding-error :text "Unexpected SignatureAlgorithm"))
	     (cons signature-algorithm digest-algorithm)))
    :issuer
    (progn (unless (eql (first issuer) :sequence)
	     (error 'x509-decoding-error
		    :text "Signature algorithm field should begin with an OID"))
	   (parse-directory-name (second issuer)))
    :validity
    (progn
      (unless (eql (first validity) :sequence)
	(error 'x509-decoding-error :text "Validity field should be an ASN.1 sequence"))
      (setf validity (second validity))
      (loop for time in validity do
	(unless (or (and (eql (first time) :utc-time)
			 (= (length (second time)) 13)
			 (every #'digit-char-p (subseq (second time) 0 12)))
		    (and (eql (first time) :generalized-time)
			 (= (length (second time)) 15)
			 (every #'digit-char-p (subseq (second time) 0 14))))
	  (error 'x509-decoding-error :text "Invalid encoding-validity field")))
      (let (dates)
	(setf (getf dates :not-before)
	      (asn-time-to-universal-time (second (first validity))))
	(setf (getf dates :not-after)
	      (asn-time-to-universal-time (second (second validity))))
	dates))
    :subject
    (progn
      (unless (eql (first subject) :sequence)
	(error 'x509-decoding-error
	       :text "Signature algorithm field should begin with an OID"))
      (parse-directory-name (second subject)))
    :subject-pki
    (let (pk)
      (unless (eql (first subject-public-key-info) :sequence)
	(error 'x509-decoding-error
	       :text "SubjectPublicKeyInfo field should be an ASN.1 sequence"))
      (setf subject-public-key-info (second subject-public-key-info))
      (unless (and (= 2 (length subject-public-key-info))
		   (eql (first (first subject-public-key-info)) :sequence)
		   (eql (first (second subject-public-key-info)) :bit-string))
	(error 'x509-decoding-error
	       :text "Length or type mismatch in SubjectPublicKeyInfo field"))
      ;; AlgorithmIdentifier
      (setf (getf pk :algorithm-identifier)
	    (parse-pka (second (first subject-public-key-info))))
      ;; subjectPublicKey
      (setf (getf pk :subject-public-key)
	    (parse-pub-key (second (second subject-public-key-info))
			   (car (getf pk :algorithm-identifier))))
      pk)
    :extensions (when extensions
		  (process-extensions extensions)))))

(defun x509-decode (octet-vector)
  "Deserialize an x509 certificate from an octet-vector"
  (let* ((x509 (make-instance 'x509v3-certificate :raw octet-vector :hash (ironclad:digest-sequence :sha3/224 octet-vector)))
	 (certificate
	   (multiple-value-bind (element-type contents)
	       (parse-der octet-vector)
	     (unless (eql element-type :sequence)
	       (error 'x509-decoding-error
		      :text "Expected ASN.1 sequence. Element: certificate"))
	     contents)))
    (unless (= (length certificate) 3)
      (error 'x509-decoding-error "Invalid certificate"))
    (destructuring-bind (tbs-certificate signature-algorithm signature) certificate
      (unless (eql (first tbs-certificate) :sequence)
	(error 'x509-decoding-error
	       :text "Expected ASN.1 sequence. Element: tbs-certificate"))
      (unless (eql (first signature-algorithm) :sequence)
	(error 'x509-decoding-error
	       :text "Expected ASN.1 sequence. Element: signature-algorithm"))
      (unless (eql (first signature) :bit-string)
	(error 'x509-decoding-error :text "Expected ASN.1 bit string. Element: signature"))
      ;; Certificate signature
      (setf (signature x509) (second signature))
      ;; Certificate signature algorithm
      (multiple-value-bind (signature-algorithm digest-algorithm)
	  (parse-signature-algorithm (second signature-algorithm))
	(setf (signature-algorithm x509)
	      (cons signature-algorithm digest-algorithm)))
      ;; TBScertificate
      (setf (tbs-certificate x509)
	    (parse-tbs-certificate (second tbs-certificate))))
    x509))

(defun asn-time-to-universal-time (time-string)
  "Converts utcTime or GeneralTime to universal time"
  (case (length time-string)
    (13;;UTCTime := YYMMDDHHMMSSZ
     (encode-universal-time (parse-integer (subseq time-string 10 12))
			    (parse-integer (subseq time-string 8 10))
			    (parse-integer (subseq time-string 6 8))
			    (parse-integer (subseq time-string 4 6))
			    (parse-integer (subseq time-string 2 4))
			    (parse-integer (subseq time-string 0 2))))
    (15;;GeneralizedTime := YYYYMMDDHHMMSSZ
     (encode-universal-time (parse-integer (subseq time-string 12 14))
			    (parse-integer (subseq time-string 10 12))
			    (parse-integer (subseq time-string 8 10))
			    (parse-integer (subseq time-string 6 8))
			    (parse-integer (subseq time-string 4 6))
			    (parse-integer (subseq time-string 0 4))))))

(defun get-raw-tbs (cert)
  "Get the raw octets of the DER-encoded tbsCertificate structure"
  (with-slots (raw) cert
    (let* ((certificate (asn-sequence-to-indices raw))
	   (tbs-certificate (first certificate))
	   (contents-start (second tbs-certificate))
	   (contents-end (third tbs-certificate))
	   (length (- contents-end contents-start)))
      (if (<= length 127)
	  (subseq raw (- contents-start 2) contents-end)
	  (subseq raw (- contents-start 2 (bytes-in-int length)) contents-end)))))

(defun verify-signature (subject issuer)
  (with-slots ((subject-tbs-certificate tbs-certificate)
	       (subject-signature signature)
	       (subject-signature-algorithm signature-algorithm)) subject
    (with-slots ((issuer-tbs-certificate tbs-certificate)) issuer
      (let* ((signature-algorithm-id subject-signature-algorithm)
	     (signature-algorithm (car signature-algorithm-id))
	     (digest-algorithm (cdr signature-algorithm-id))
	     (verification-digest (ironclad:digest-sequence
				   digest-algorithm
				   (get-raw-tbs subject)))
	     (signature (subseq subject-signature 1))
	     (issuer-pk (getf (subject-pki issuer-tbs-certificate)
			      :subject-public-key)))
	(case signature-algorithm
	  (:rsa
	   (let ((pub-key (ironclad:make-public-key :rsa
						    :n (getf issuer-pk :modulus)
						    :e (getf issuer-pk :public-exponent))))
	     (setf signature (rsa-encrypt signature pub-key))
	     (unless (= (aref signature 1) 1)
	       (return-from verify-signature nil))
	     (setf signature (subseq signature (1+ (position 0 signature :start 1))))
	     (multiple-value-bind (asn-type digest-info) (parse-der signature)
	       (unless (and (eql asn-type :sequence)
			    (= (length digest-info) 2))
		 (return-from verify-signature nil))
	       (destructuring-bind (digest-algorithm digest) digest-info
		 (declare (ignorable digest-algorithm))
		 (unless (eql (first digest) :octet-string) (return-from verify-signature nil))
		 (setf digest (second digest))
		 (timing-independent-compare verification-digest digest)))))
	  (:dsa
	   (let ((pub-key
		   (ironclad:make-public-key :dsa
					     :p (getf issuer-pk :dsa-p)
					     :q (getf issuer-pk :dsa-q)
					     :g (getf issuer-pk :dsa-g)
					     :y (getf issuer-pk :dsa-public-key))))
	     (multiple-value-bind (asn-type dss-sig-value) (parse-der signature)
	       (unless (and (eql asn-type :sequence)
			    (= (length dss-sig-value) 2))
		 (return-from verify-signature nil))
	       (unless (every (lambda (arg) (asn-type-matches-p :integer arg)) dss-sig-value))
	       (destructuring-bind (r s) dss-sig-value
		 (setf signature (ironclad:make-signature :dsa :r (second r) :s (second s)))
		 (ironclad:verify-signature pub-key verification-digest signature))))))))))

(defun time-valid-p (cert)
  (let* ((validity (validity (tbs-certificate cert)))
	 (not-before (getf validity :not-before))
	 (not-after (getf validity :not-after))
	 (current-time
	   (handler-case
	       (get-universal-time)
	     (error ()
	       (error 'exception
		      :log "Could not determine system time for certificate validation"
		      :alert :internal-error)))))
    (<= not-before current-time not-after)))
