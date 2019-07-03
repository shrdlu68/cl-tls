;; An implementation of PBES2. See rfc2898
;; PBES2-params ::= SEQUENCE {
;; keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
;;        encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }
(in-package :cl-tls)

(defun parse-kdf (kdf)
  (let (salt iteration-count key-length pbkdf2-prf)
    (unless (and (eql (first (first kdf)) :oid)
		 (eql (first (second kdf)) :sequence))
      (error "Malformed keyDerivationFunc sequence"))
    (unless (equal '(1 2 840 113549 1 5 12) (second (first kdf)))
      (error "Only PBKDF2 is supported"))
    (let ((pbkdf2-params (second (second kdf))))
      ;; PBKDF2-params ::= SEQUENCE {
      ;; salt CHOICE {
      ;; specified OCTET STRING,
      ;; otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
      ;; },
      ;; iterationCount INTEGER (1..MAX),
      ;; keyLength INTEGER (1..MAX) OPTIONAL,
      ;; prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1 }
      (unless (<= 2 (length pbkdf2-params) 4)
	(error "Malformed PBKDF2-params sequence"))
      (cond ((eql (first (first pbkdf2-params)) :octet-string)
	     (setf salt (second (first pbkdf2-params))))
	    ((eql (first (first pbkdf2-params)) :oid)
	     (error "PBKDF2-SaltSources is not supported"))
	    (t
	     (error "Malformed PBKDF2-params sequence")))
      (if (eql (first (second pbkdf2-params)) :integer)
	  (setf iteration-count (second (second pbkdf2-params)))
	  (error "Malformed PBKDF2-params sequence"))
      (when (third pbkdf2-params)
	(if (eql (first (third pbkdf2-params)) :integer)
	    (setf key-length (second (third pbkdf2-params)))
	    (error "Malformed PBKDF2-params sequence"))
	(when (fourth pbkdf2-params)
	  (if (eql (first (fourth pbkdf2-params)) :sequence)
	      (let* ((prf (second (fourth pbkdf2-params)))
		     (alg-id (if (eql (first (first prf)) :oid)
				 (second (first prf))
				 (error "Malformed PBKDF2-params sequence"))))
		(unless (and (= (length alg-id) 6)
			     (equal (butlast alg-id) '(1 2 840 113549 2)))
		  (error "Expected {rsadsi 2}"))
		(setf pbkdf2-prf
		      (case (sixth alg-id)
			(7 :sha1)
			(8 :sha224)
			(9 :sha256)
			(10 :sha384)
			(11 :sha512)
			(otherwise (error "Unrecognized or unsupported PBKDF2 PRF OID"))))))))
      (values salt iteration-count key-length pbkdf2-prf))))

(defun parse-enc-scheme (enc-scheme)
  (unless (and (= (length enc-scheme) 2)
	       (eql (first (first enc-scheme)) :oid)
	       (find (first (second enc-scheme)) '(:octet-string :sequence)))
    (error "Invalid PBES2 encryptionScheme formatting"))
  (destructuring-bind (oid params)
      (list (second (first enc-scheme))
	    (second enc-scheme))
    (cond
      ((equal oid '(1 3 6 1 4 1 188 7 1 1 2))
       (values :idea-cbc
	       (if (eql (first params) :octet-string)
		   (second params)
		   (error "Expecting octet string in PBES2 encryptionScheme parameters"))))
      ((equal (butlast oid) '(2 16 840 1 101 3 4 1))
       (values (case (ninth oid)
		 (2 :aes-128)
		 (22 :aes-192)
		 (42 :aes-256))
	       (if (eql (first params) :octet-string)
		   (second params)
		   (error "Expecting octet string in PBES2 encryptionScheme parameters"))))
      ((equal oid '(1 2 840 113549 3 2))
       (values :rc2-cbc-pad
	       (if (eql (first params) :sequence)
		   (let ((rc2-cbc-params (second params)))
		     (if (= (length rc2-cbc-params) 1)
			 (list 32 (second (first rc2-cbc-params)))
			 (progn (unless (and (= (length rc2-cbc-params) 2)
					     (eql (first (first rc2-cbc-params)) :integer)
					     (eql (first (second rc2-cbc-params)) :octet-string))
				  (error "Invalid RC2-CBC params"))
				(list (let ((effective-key-bits (second (first rc2-cbc-params))))
					(case effective-key-bits
					  (160 40)
					  (120 64)
					  (58 128)
					  (otherwise effective-key-bits)))
				      (second (second rc2-cbc-params))))))
		   (error "Expecting Sequence as RC2-CBC params"))))
      ;; (3 :rc2-ecb)
      ;; (4 :rc4)
      ;; (5 :rc4-with-mac)
      ((equal oid '(1 2 840 113549 3 7))
       (values :des3-cbc
	       (if (eql (first params) :octet-string)
		   (second params)
		   (error "Expecting octet string in PBES2 encryptionScheme parameters"))))
      ;; (8 :rc5-cbc)
      ((equal oid '(1 2 840 113549 3 9))
       (values :rc5-cbc-pad
	       (if (eql (first params) :sequence)
		   (let ((rc5-cbc-params (second params)))
		     (cond ((= (length rc5-cbc-params) 4)
			    (unless (and (every (lambda (li) (eql (first li) :integer)) (butlast rc5-cbc-params))
					 (eql (first (fourth rc5-cbc-params)) :octet-string))
			      (error "Invalid RC5-CBC-Pad Parameters"))
			    (loop for el in rc5-cbc-params collecting
							   (if (eql (first el) :integer)
							       (second el)
							       (second el))))
			   ((= (length rc5-cbc-params) 3)
			    (unless (every (lambda (li) (eql (first li) :integer)) (butlast rc5-cbc-params))
			      (error "Invalid RC5-CBC-Pad Parameters"))
			    (loop for el in rc5-cbc-params collecting
							   (second el)))
			   (t
			    (error "Invalid RC5-CBC-Pad Parameters")))))))
      (t (error "Unsupported encryption algorithm")))))

(defun remove-padding (ov)
  "Remove rfc1423 padding from octet-vector ov"
  (defparameter foo ov)
  (let* ((ov-len (length ov))
	 (padding-length (aref ov (1- ov-len)))
	 (padding-octets (if (< padding-length ov-len)
			     (subseq ov (- ov-len padding-length))
			     (error "Ivalid PBES2 padding"))))
    (unless (every (lambda (n) (= n padding-length)) padding-octets)
      (error "Invalid PBES2 padding"))
    (adjust-array ov (- ov-len padding-length))))

(defun pbes2-decrypt (ov &optional passphrase)
  (let ((data (multiple-value-bind (element-type element-octets)
		  (parse-der ov)
		(unless (eql :sequence element-type)
		  (error "Expected an ASN.1 sequence in PKCS#5-encypted data"))
		element-octets)))
    (unless (and (= (length data) 2)
		 (eql (first (first data)) :sequence)
		 (eql (first (second data)) :octet-string))
      (error "Invalid PKCS#5 encoding"))
    ;; EncryptedPrivateKeyInfo ::= SEQUENCE {
    ;; encryptionAlgorithm  EncryptionAlgorithmIdentifier,
    ;;         encryptedData        EncryptedData }
    (destructuring-bind (enc-algorithm encrypted-data)
	(list (second (first data))
	      (second (second data)))
      (unless (and (= (length enc-algorithm) 2)
		   (eql (first (first enc-algorithm)) :oid)
		   (eql (first (second enc-algorithm)) :sequence))
	(error "Invalid PKCS#5 encoding"))
      ;; id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13}
      ;; PBES2-params ::= SEQUENCE {
      ;; keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
      ;;        encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }
      (destructuring-bind (enc-scheme-identifier enc-scheme-params)
	  (list (second (first enc-algorithm))
		(second (second enc-algorithm)))
	(unless (equal '(1 2 840 113549 1 5 13) enc-scheme-identifier)
	  (error "Only PBES2 encyption scheme is supported."))
	(unless (every (lambda (el) (eql (first el) :sequence)) enc-scheme-params)
	  (error "Malformed PBES2-params"))
	(destructuring-bind (kdf enc-scheme)
	    (loop for el in enc-scheme-params collecting
					      (second el))
	  (multiple-value-bind (enc-algorithm params) (parse-enc-scheme enc-scheme)
	    (multiple-value-bind (salt iteration-count key-length prf) (parse-kdf kdf)
	      (unless key-length
		(setf key-length
		      (case enc-algorithm
			(:aes-128 16)
			(:aes-192 24)
			(:aes-256 32)
			(:idea-cbc 16)
			(:des3-cbc 24)
			(:rc2-cbc-pad (/ (first params) 8)))))
	      (unless prf
		(setf prf :sha1))
	      (setf prf (find-symbol (string prf) :ironclad))
	      (let ((key (ironclad:derive-key
			  (ironclad:make-kdf 'ironclad:pbkdf2 :digest prf)
			  (ironclad:ascii-string-to-byte-array passphrase)
			  (make-octet-vector :initial-contents salt) iteration-count key-length))
		    (plaintext (make-octet-vector :length (length encrypted-data))))
		(setf encrypted-data (make-octet-vector :initial-contents encrypted-data))
		(cond
		  ((or (eql enc-algorithm :aes-128)
		       (eql enc-algorithm :aes-192)
		       (eql enc-algorithm :aes-256))
		   (ironclad:decrypt
		    (ironclad:make-cipher :aes :key key :mode :cbc
					       :initialization-vector
					       (make-octet-vector :initial-contents params))
		    encrypted-data plaintext))
		  ((eql enc-algorithm :idea-cbc)
		   (ironclad:decrypt
		    (ironclad:make-cipher :idea :key key :mode :cbc
						:initialization-vector
						(make-octet-vector :initial-contents params))
		    encrypted-data plaintext))
		  ((eql enc-algorithm :des3-cbc)
		   (ironclad:decrypt
		    (ironclad:make-cipher :3des :key key :mode :cbc
						:initialization-vector
						(make-octet-vector :initial-contents params))
		    encrypted-data plaintext))
		  ((eql enc-algorithm :rc2-cbc-pad)
		   (ironclad:decrypt
		    (ironclad:make-cipher :rc2 :key key :mode :cbc
					       :initialization-vector
					       (make-octet-vector
						:initial-contents (second params)))
		    encrypted-data plaintext))
		  ;; Don't know how to pass rounds param to ironclad's rc5, so pass over for now
		  ;; My tests with openssl show that it does not encode a Blowfish key length,
		  ;; so pass for now too.
		  )
		(remove-padding plaintext)))))))))
