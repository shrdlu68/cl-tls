;; Implements the encryption-block formatting defined in RFC2313
(in-package :cl-tls)

(defun fill-random-nonzero-octets(buffer &optional (start 0) end)
  (with-open-file (dev-urandom "/dev/urandom" :direction :input :element-type 'octet)
    (unless end (setf end (length buffer)))
    (loop for n from start below end do
	 (setf (aref buffer n) (loop for R = (read-byte dev-urandom)
				    when (plusp R) do (return R))))
    (- end start)))

(defun rsa-encrypt (data key)
  "Converts data into an encryption block then calls ironclad"
  (let* ((destructured-key (if (typep key 'ironclad::rsa-private-key)
			       (ironclad:destructure-private-key key)
			       (ironclad:destructure-public-key key)))
	 (k (/ (integer-length (getf destructured-key :n)) 8))
	 (D (length data))
	 (padding-length (- k 3 D))
	 (eb (make-array (+ 3 padding-length D) :element-type 'octet)))
    ;; (assert (<= D (- k 11)))
    ;; BT
    (setf (aref eb 1) (if (typep key 'ironclad::rsa-private-key)
			  #x01
			  #x02))
    ;; PS
    (fill-random-nonzero-octets eb 2 (+ 2 padding-length))
    ;; D
    (replace eb data :start1 (+ 3 padding-length))
    (ironclad:encrypt-message key eb)))

(defun rsa-decrypt (data private-key)
  "Returns raw data after decrypting and parsing the Encryption-block"
  (setf data (ironclad:decrypt-message private-key data))
  (case (aref data 0)
    (#x02;; We only expect pub-key operations
     (subseq data (1+ (position 0 data))))
    (otherwise
     nil)))

(defun emsa-pkcs1-v1.5-encode (M emLen hash-algorithm)
  (let* ((H (ironclad:digest-sequence hash-algorithm M))
	 (algorithm-identifier
	  (cat-vectors
	   (asn-serialize (case hash-algorithm
			    (:md5 '(1 2 840 113549 2 5))
			    (:sha1 '(1 3 14 3 2 26))
			    (:sha256 '(2 16 840 1 101 3 4 2 1))
			    (:sha384 '(2 16 840 1 101 3 4 2 2))
			    (:sha512 '(2 16 840 1 101 3 4 2 3)))
			  :oid)
	   (asn-serialize nil :null)))
	 (TT (create-asn-sequence
	      (list algorithm-identifier :sequence)
	      (list H :octet-string)))
	 (tLen (length TT)))
    (if (< emLen (+ tLen 11))
	(error "RSASSA-PKCS1.5: Intended encoded message length too short"))
    (let* ((PS (fill
		(fast-io:make-octet-vector (- emLen tLen 3))
		#xff)))
      (assert (>= (length PS) 8))
      (fast-io:with-fast-output (out)
	(fast-io:fast-write-byte #x00 out)
	(fast-io:fast-write-byte #x01 out)
	(fast-io:fast-write-sequence PS out)
	(fast-io:fast-write-byte #x00 out)
	(fast-io:fast-write-sequence TT out)))))
	 

(defun rsassa-pkcs1.5-sign (priv-key msg hash-algorithm)
  (let* ((e (getf (ironclad:destructure-private-key priv-key) :n))
	 (k (ceiling (integer-length e) 8))
	 (EM (emsa-pkcs1-v1.5-encode msg k hash-algorithm)))
    (ironclad:decrypt-message priv-key EM)))

(defun rsassa-pkcs1.5-verify (pub-key msg signature hash-algorithm)
  (let* ((e (getf (ironclad:destructure-public-key pub-key) :n))
	 (k (ceiling (integer-length e) 8)))
    (or (= (length signature) k)
	(return-from rsassa-pkcs1.5-verify nil))
    (let* ((M (ironclad:encrypt-message pub-key signature))
	   (EM (subseq (emsa-pkcs1-v1.5-encode msg k hash-algorithm) 1)))
      (timing-independent-compare M EM))))
