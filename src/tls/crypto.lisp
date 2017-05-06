(in-package :cl-tls)
;; P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
;;         	      	  HMAC_hash(secret, A(2) + seed) +
;;                        HMAC_hash(secret, A(3) + seed) + ...
;; A()
;; A(0) = seed
;;       A(i) = HMAC_hash(secret, A(i-1))
(defun p-hash (secret data output-length &optional (digest-algorithm :sha256))
  (let ((output (make-array output-length :element-type 'octet)))
    (loop
       with digest-size = (ironclad:digest-length digest-algorithm)
       for hmac = (ironclad:make-hmac secret digest-algorithm)
       then (reinitialize-instance hmac :key secret)
       for A = (progn
		 (ironclad:update-hmac hmac data)
		 (ironclad:hmac-digest hmac))
       then (progn
	      (ironclad:update-hmac hmac A)
	      (ironclad:hmac-digest hmac))
       for output-offset = 0 then (+ output-offset digest-size)
       while (< output-offset output-length)
       do
	 (setf hmac (reinitialize-instance hmac :key secret))
	 (ironclad:update-hmac hmac (cat-vectors A data))
	 (replace output (ironclad:hmac-digest hmac) :start1 output-offset))
    output))

(defun prf (secret label seed output-length)
  (p-hash secret (cat-vectors (ironclad:ascii-string-to-byte-array label) seed)
	  output-length))

;; master_secret = PRF(pre_master_secret, "master secret",
;; 				       ClientHello.random + ServerHello.random)
;;                           	       [0..47];
;; key_block = PRF(SecurityParameters.master_secret,
;; 		"key expansion",
;; 		SecurityParameters.server_random +
;; 		SecurityParameters.client_random);

(define-symbol-macro endpoint-encryption-key
    (if (eql role :client)
	client-write-key
	server-write-key))

(define-symbol-macro endpoint-decryption-key
    (if (eql role :client)
	server-write-key
	client-write-key))

(defun gen-key-material (client)
  "Generate the session keying material"
  (with-slots (master-secret pre-master-secret client-random server-random mac-key-length
			     enc-key-length role record-iv-length client-write-mac-key
			     server-write-mac-key client-write-key server-write-key
			     client-write-iv server-write-iv cipher-type encryption-algorithm
			     encrypting-cipher-object decrypting-cipher-object)
      client
    (setf master-secret
	  (prf pre-master-secret "master secret"
	       (cat-vectors client-random server-random) 48))
    ;; Spec recommends this
    (fill pre-master-secret #x0)
    (setf pre-master-secret nil)
    (let ((key-block (prf master-secret "key expansion"
			  (cat-vectors server-random client-random)
			  (* 2 (+ mac-key-length enc-key-length record-iv-length))))
	  (key-offset 0))
      (setf client-write-mac-key (subseq key-block key-offset mac-key-length))
      (incf key-offset mac-key-length)
      (setf server-write-mac-key (subseq key-block key-offset (+ key-offset mac-key-length)))
      (incf key-offset mac-key-length)
      (setf client-write-key (subseq key-block key-offset (+ key-offset enc-key-length)))
      (incf key-offset enc-key-length)
      (setf server-write-key (subseq key-block key-offset (+ key-offset enc-key-length)))
      (incf key-offset enc-key-length)
      (when (eql cipher-type :block)
	  (setf client-write-iv
		(subseq key-block key-offset (+ key-offset record-iv-length)))
	  (incf key-offset record-iv-length)
	  (setf server-write-iv
		(subseq key-block key-offset (+ key-offset record-iv-length)))))
    ;; (format t "~&Client-write-mac-key: ~S~%" client-write-mac-key)
    ;; (format t "~&Server-write-mac-key: ~S~%" server-write-mac-key)
    ;; (format t "~&Client-write-key: ~S~%" client-write-key)
    ;; (format t "~&Server-write-key: ~S~%" server-write-key)
    ;; (format t "~&Client-write-iv: ~S~%" client-write-iv)
    ;; (format t "~&Server-write-iv: ~S~%" server-write-iv)
    ;; Stream ciphers such as RC4 need to store a cipher state
    (when (eql encryption-algorithm :rc4)
      (setf encrypting-cipher-object
	    (ironclad:make-cipher :arcfour :key endpoint-encryption-key :mode :stream))
      (setf decrypting-cipher-object
	    (ironclad:make-cipher :arcfour :key endpoint-decryption-key :mode :stream)))))

;; struct {
;; SignatureAndHashAlgorithm algorithm;
;; opaque signature<0..2^16-1>;
;;       } DigitallySigned;

(defun digitally-sign (session data)
  "Create a digitally-signed-struct"
  (with-slots (extensions-data
	       authentication-method client-random server-random
	       key-exchange-method priv-key supported-sig-algos
	       certificate) session
    (let* ((supported-signature-algorithms
	    (supported-signature-algorithms extensions-data))
	   (algos (or
		   (loop
		      for sig in supported-sig-algos
		      when
			(eql (second sig)
			     (first
			      (getf (subject-pki
				     (tbs-certificate (x509-decode (first certificate))))
				    :algorithm-identifier))) return sig)
		   (or (and supported-signature-algorithms
			    (loop
			       for sig in supported-signature-algorithms
			       do
				 (when (eql (second sig) authentication-method)
				   (return sig))))
		       (cond ((and (member key-exchange-method
					   '(:rsa :dhe :dh :ecdh :ecdhe))
				   (member authentication-method
					   '(:rsa :psk )))
			      '(:sha1 :rsa))
			     ((and (member key-exchange-method '(:dh :dhe))
				   (eql authentication-method :dsa))
			      '(:sha1 :dsa))
			     ((and (member key-exchange-method '(:ecdh :ecdhe))
				   (eql authentication-method :dsa))
			      '(:sha1 :ecdsa)))))))
      (destructuring-bind (hash-algorithm signature-algorithm) algos
	(fast-io:with-fast-output (out)
	  (fast-io:fast-write-byte
	   (ecase hash-algorithm
	     (:md5 1) (:sha1 2) (:sha224 3) (:sha256 4) (:sha384 5)
	     (:sha512 6)) out)
	  (fast-io:fast-write-byte
	   (case signature-algorithm
	     (:rsa 1) (:dsa 2) (:ecdsa 3)) out)
	  (case signature-algorithm
	    (:dsa
	     (let* ((digest (ironclad:digest-sequence (first algos) data))
		    (raw-signature (ironclad:sign-message priv-key digest))
		    (signature
		     (create-asn-sequence
		      (list (ironclad:dsa-signature-r raw-signature) :integer)
		      (list (ironclad:dsa-signature-s raw-signature) :integer))))
	       (fast-io:writeu16-be (length signature) out)
	       (fast-io:fast-write-sequence signature out)))
	    (:rsa
	     (let ((signature
		    (rsassa-pkcs1.5-sign priv-key data hash-algorithm)))
	       (fast-io:writeu16-be (length signature) out)
	       (fast-io:fast-write-sequence signature out)))
	    (:ecdsa
	     ;; TODO
	     )))))))

(defun verify-signed-data (session data algorithm signature)
  (with-slots (pub-key) session
    (flet ((fail () (return-from verify-signed-data nil)))
      (let ((hash-alg (case (aref algorithm 0)
			(1 :md5) (2 :sha1) (3 :sha224) (4 :sha256)
			(5 :sha384) (6 :sha512) (otherwise (fail))))
	    (signature-alg (case (aref algorithm 1)
			     (1 :rsa) (2 :dsa) (3 :ecdsa) (otherwise (fail)))))
	(case signature-alg
	  (:dsa
	   (let ((digest (ironclad:digest-sequence hash-alg data)))
	     (multiple-value-bind (type contents) (parse-der signature)
	       (unless (and (eql type :sequence)
			    (= (length contents) 2)
			    (every (lambda (arg)
				     (asn-type-matches-p :integer arg))
				   contents))
		 (fail))
	       (destructuring-bind (r s) contents
		 (ironclad:verify-signature
		  pub-key digest (ironclad:make-dsa-signature (second r) (second s)))))))
	  (:rsa
	   (rsassa-pkcs1.5-verify pub-key data signature hash-alg))
	  (:ecdsa
	   ;; TODO
	   nil))))))

(defun sign-dh-params (session params)
  (with-slots (client-random server-random) session
    (let ((data (cat-vectors client-random server-random params)))
      (digitally-sign session data))))

(defun verify-signed-params (session dh-params algorithm signature)
  (with-slots (client-random server-random) session
    (let ((data (cat-vectors client-random server-random dh-params)))
      (verify-signed-data session data algorithm signature))))
