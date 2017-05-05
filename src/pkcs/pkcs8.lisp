;; An implementation of PKCS#8, see rfc5208
(in-package :cl-tls)

(defun parse-priv-key (ov private-key-algorithm)
  (let (private-key-info)
    (case private-key-algorithm
      ;; RSAPrivateKey ::= SEQUENCE {
      ;; version Version,
      ;; modulus INTEGER, -- n
      ;; publicExponent INTEGER, -- e
      ;; privateExponent INTEGER, -- d
      ;; prime1 INTEGER, -- p
      ;; prime2 INTEGER, -- q
      ;; exponent1 INTEGER, -- d mod (p-1)
      ;; exponent2 INTEGER, -- d mod (q-1)
      ;; coefficient INTEGER -- (inverse of q) mod p }
      ;;    Version ::= INTEGER
      (:rsa
       (let ((rsa-private-key (multiple-value-list
			       (parse-der ov))))
	 (unless (eql (first rsa-private-key) :sequence)
	   (error 'x509-decoding-error "The RSAPrivateKey should contain an ASN.1 sequence"))
	 (setf rsa-private-key (second rsa-private-key))
	 (unless (= (length rsa-private-key) 9)
	   (error "RSAPrivateKey ASN.1 sequence should have 9 elements"))
	 (loop for element in rsa-private-key do
	   (unless (eql (first element) :integer)
	     (error 'x509-decoding-error :text "Expected integers in RSAPrivateKey.")))
	 (setf (getf private-key-info :version)
	       (second (first rsa-private-key)))
	 (setf (getf private-key-info :modulus)
	       (second (second rsa-private-key)))
	 (setf (getf private-key-info :public-exponent)
	       (second (third rsa-private-key)))
	 (setf (getf private-key-info :private-exponent)
	       (second (fourth rsa-private-key)))
	 (setf (getf private-key-info :p)
	       (second (fifth rsa-private-key)))
	 (setf (getf private-key-info :q)
	       (second (sixth rsa-private-key)))
	 (setf (getf private-key-info :exponent1)
	       (second (seventh rsa-private-key)))
	 (setf (getf private-key-info :exponent2)
	       (second (eighth rsa-private-key)))
	 (setf (getf private-key-info :coefficient)
	       (second (ninth rsa-private-key)))))
      ;; DSAPrivateKey ::= OCTETSTRING {
      ;; privateExponent INTEGER
      ;; }
      (:dsa
       (let ((dsa-private-key (multiple-value-list
			       (parse-der ov))))
	 (unless (eql (first dsa-private-key) :integer)
	   (error "Expected a DSA private key"))
	 (setf (getf private-key-info :dsa-private-exponent) (second dsa-private-key))))
      ;; DH --see PKCS#3
      (:dh
       (let ((dh-private-value (multiple-value-list
				(parse-der ov))))
	 (unless (eql (first dh-private-value) :integer)
	   (error 'x509-decoding-error :text "Invalid encoding of DHPrivateValue"))
	 (setf (getf private-key-info :dh-X) (second dh-private-value)))))
    private-key-info))

(defun load-der-priv-key (octet-vector)
  "Load a PKCS#8-encoded (rfc5208) private key file"
  (let* ((pki (multiple-value-bind (element-type contents)
		  (parse-der octet-vector)
		(unless (eql element-type :sequence)
		  (error
		   "Error Loading Private Key: The encoding is erroneous or unrecognized"))
	        contents)))
    ;; EncryptedPrivateKeyInfo ::= SEQUENCE {
    ;; encryptionAlgorithm  EncryptionAlgorithmIdentifier,
    ;;         encryptedData        EncryptedData }
    (when (= 2 (length pki))
      (setf octet-vector
	    (pbes2-decrypt octet-vector
			   (progn
			     (format t
				     "~&Enter the passphrase for the private key file:~%")
			     (read-line))))
      (setf pki (multiple-value-bind (element-type contents)
		    (parse-der octet-vector)
		  (unless (eql :sequence element-type)
		    (error
		     "Error Loading Private Key: The encoding of the key is erroneous or unrecognized"))
		  contents)))
    ;; Version ::= INTEGER TODO: Ignore for now
    ;; PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    (let ((algorithm-identifier (parse-pka (second (second pki)))))
      ;; PrivateKey ::= OCTET STRING
      (append (list :private-key-algorithm (car algorithm-identifier))
	      (list :private-key-parameters (cdr algorithm-identifier))
	      (parse-priv-key (second (third pki)) (car algorithm-identifier))))))

(defun load-pem-priv-key (character-vector)
  "Load a PEM-encoded Private key; PEM-encoded keys should be just base64-encoded PKCS#8
PrivateKeyInfo structures with a header and a footer. But they're sometimes not, instead being just the
privateKey-RSAPrivateKey and DSAPrivateKey."
  (let ((pem (first (parse-pem character-vector)))
	key)
    (cond
      ((equal (car pem) "RSA PRIVATE KEY")
       (setf key (parse-priv-key (cdr pem) :rsa))
       (setf key (append (list :private-key-algorithm :rsa)
			 key)))
      ((equal (car pem) "DSA PRIVATE KEY")
       ;; Compatibility with keys encoded as a sequence containing
       ;; the version p, q, g, public, and private components
       (multiple-value-bind (asn-type contents) (parse-der (cdr pem))
	 (unless (and (eql asn-type :sequence)
		      (= (length contents) 6)
		      (every #'(lambda (arg) (asn-type-matches-p :integer arg))
			     contents))
	   (error "Could load load private key, unknown encoding" ))
	 (destructuring-bind (v p q g y x) contents
	   (declare (ignorable v))
	   (setf key (list :private-key-algorithm :dsa
			   :dsa-p (second p)
			   :dsa-q (second q)
			   :dsa-g (second g)
			   :dsa-x (second x)
			   :dsa-y (second y))))))
      ((or (equal (car pem) "PRIVATE KEY")
	   (equal (car pem) "ENCRYPTED PRIVATE KEY"))
       (return-from load-pem-priv-key (load-der-priv-key (cdr pem)))))
    key))

(defun load-priv-key (obj)
  (typecase obj
    ((simple-array (unsigned-byte 8) *)
     (load-der-priv-key obj))
    ((simple-array character *)
     (load-pem-priv-key obj))))
