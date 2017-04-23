;; An implementation of PKCS#8, see rfc5208
(in-package :cl-tls)

(defun parse-priv-key (ov ht)
  (case (gethash :public-key-algorithm ht)
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
       (setf (gethash :version ht) (second (first rsa-private-key)))
       (setf (gethash :modulus ht) (second (second rsa-private-key)))
       (setf (gethash :public-exponent ht) (second (third rsa-private-key)))
       (setf (gethash :private-exponent ht) (second (fourth rsa-private-key)))
       (setf (gethash :p ht) (second (fifth rsa-private-key)))
       (setf (gethash :q ht) (second (sixth rsa-private-key)))
       (setf (gethash :exponent1 ht) (second (seventh rsa-private-key)))
       (setf (gethash :exponent2 ht) (second (eighth rsa-private-key)))
       (setf (gethash :coefficient ht) (second (ninth rsa-private-key)))))
    ;; DSAPrivateKey ::= OCTETSTRING {
    ;; privateExponent INTEGER
    ;; }
    (:dsa
     (let ((dsa-private-key (multiple-value-list
			    (parse-der ov))))
       (unless (eql (first dsa-private-key) :integer)
	 (error "Expected a DSA private key"))
       (setf (gethash :dsa-private-exponent ht) (second dsa-private-key))))
    ;; DH --see PKCS#3
    (:dh
     (let ((dh-private-value (multiple-value-list
			     (parse-der ov))))
       (unless (eql (first dh-private-value) :integer)
	 (error 'x509-decoding-error :text "Invalid encoding of DHPrivateValue"))
       (setf (gethash :dh-X ht) (second dh-private-value))))))

(defun load-der-priv-key (octet-vector)
  "Load a PKCS#8-encoded (rfc5208) private key file"
  (let* ((pki (multiple-value-bind (element-type contents)
		  (parse-der octet-vector)
		(unless (eql element-type :sequence)
		  (error "Error Loading Private Key: The encoding is erroneous or unrecognized"))
	        contents))
	 (key (make-hash-table)))
    ;; EncryptedPrivateKeyInfo ::= SEQUENCE {
    ;; encryptionAlgorithm  EncryptionAlgorithmIdentifier,
    ;;         encryptedData        EncryptedData }
    (when (= 2 (length pki))
      (setf octet-vector
	    (pbes2-decrypt octet-vector
			   (progn
			     (format t "~&Enter the passphrase for the private key file:~%")
			     (read-line))))
      (setf pki (multiple-value-bind (element-type contents)
		    (parse-der octet-vector)
		  (unless (eql :sequence element-type)
		    (error "Error Loading Private Key: The encoding of the key is erroneous or unrecognized"))
		  contents)))
    ;; Version ::= INTEGER TODO: Ignore for now
    ;; PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    (parse-pka (second (second pki)) key)
    ;; PrivateKey ::= OCTET STRING
    (parse-priv-key (second (third pki)) key)
    ;; (loop
    ;;    for k being each hash-key of key
    ;;    for v being each hash-value of key do
    ;; 	 (format t "~&~S: ~S~%" k v))
    ;; Attributes ::= SET OF Attribute TODO
    key))

(defun load-pem-priv-key (character-vector)
  "Load a PEM-encoded Private key; PEM-encoded keys should be just base64-encoded PKCS#8
PrivateKeyInfo structures with a header and a footer. But they're sometimes not, instead being just the
privateKey-RSAPrivateKey and DSAPrivateKey."
  (let ((pem (first (parse-pem character-vector)))
	(key (make-hash-table)))
    (cond
      ((equal (car pem) "RSA PRIVATE KEY")
       (setf (gethash :public-key-algorithm key) :rsa)
       (parse-priv-key (cdr pem) key))
      ((equal (car pem) "DSA PRIVATE KEY")
       (setf (gethash :public-key-algorithm key) :dsa)
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
	   (setf (gethash :dsa-p key) (second p))
	   (setf (gethash :dsa-q key) (second q))
	   (setf (gethash :dsa-g key) (second g))
	   (setf (gethash :dsa-x key) (second x))
	   (setf (gethash :dsa-y key) (second y)))))
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
