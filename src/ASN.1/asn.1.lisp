;; This parser is (so far) only as sophisticated as it needs to be to handle TLS-related structures

(in-package :cl-tls)

(defconstant +ASN1_UNIVERSAL+ #X00)
(defconstant +ASN1_APPLICATION+ #X40)
(defconstant +ASN1_CONTEXT_SPECIFIC+ #X80)
(defconstant +ASN1_PRIVATE+ #Xc0)
(defconstant +ASN1_PRIMITIVE+ #X00)
(defconstant +ASN1_CONSTRUCTED+ #X20)

(defconstant +ID_AT_COUNTRY+ 6)
(defconstant +ID_AT_ORGANIZATION+ 10)
(defconstant +ID_AT_ORGANIZATION_UNIT+ 11)
(defconstant +ID_AT_DN_QUALIFIER+ 46)
(defconstant +ID_AT_STATE_OR_PROVINCE_NAME+ 8)
(defconstant +ID_AT_COMMON_NAME+ 3)
(defconstant +ID_AT_SERIAL_NUMBER+ 5)
(defconstant +ID_AT_NAME+ 41)
(defconstant +ID_AT_SURNAME+ 4)
(defconstant +ID_AT_GIVEN_NAME+ 42)
(defconstant +ID_AT_INITIALS+ 43)
(defconstant +ID_AT_GENERATION_QUALIFIER+ 44)
(defconstant +ID_AT_LOCALITY+  7)
(defconstant +ID_AT_TITLE+ 12)
(defconstant +ID_AT_PSEUDONYM+ 65)

(define-condition asn.1-decoding-error (error)
  ((text :initarg :text :reader text)))

(defun from-stream-parse-der (octet-stream &key (mode :deserialized))
  (handler-case
      (let (element-length element-type class constructedp identifier-octet)
	(setf identifier-octet (fast-io:fast-read-byte octet-stream))
	;; Class
	(case (ldb (byte 2 6) identifier-octet)
	  (0
	   (setf class :universal))
	  (1
	   (setf class :application))
	  (2
	   (setf class :private))
	  (3
	   (setf class :context-specific)))
	;; Constructed or primitive?
	(unless (zerop (ldb (byte 1 5) identifier-octet))
	  (setf constructedp t))
	;; x509 uses tag numbers between 0 and 30, therefore we only expect the low tag form
	(if (eql class :universal)
	    (case (ldb (byte 5 0) identifier-octet)
	      ;; Universal types
	      (1
	       (setf element-type :boolean))
	      (2
	       (setf element-type :integer))
	      (3
	       (setf element-type :bit-string))
	      (4
	       (setf element-type :octet-string))
	      (5
	       (setf element-type :null))
	      (6
	       (setf element-type :oid))
	      (7
	       (setf element-type :object-descriptor))
	      (8
	       (setf element-type :instance-of))
	      (9
	       (setf element-type :real))
	      (10
	       (setf element-type :enumerated))
	      (11
	       (setf element-type :embedded-pdv))
	      (12
	       (setf element-type :utf8-string))
	      (13
	       (setf element-type :relative-oid))
	      (16
	       (setf element-type :sequence))
	      (17
	       (setf element-type :set))
	      (18
	       (setf element-type :numeric-string))
	      (19
	       (setf element-type :printable-string))
	      (20
	       (setf element-type :telex-string))
	      (21
	       (setf element-type :videotext-string))
	      (22
	       (setf element-type :ia5-string))
	      (23
	       (setf element-type :utc-time))
	      (24
	       (setf element-type :generalized-time))
	      (25
	       (setf element-type :graphic-string))
	      (26
	       (setf element-type :visible-string))
	      (27
	       (setf element-type :general-string))
	      (28
	       (setf element-type :universal-string))
	      (29
	       (setf element-type :character-string))
	      (30
	       (setf element-type :bmp-string))
	      ;; No recognized type found, return the tag number instead
	      (otherwise
	       (error 'asn.1-decoding-error :text "Unrecognized primitive tag")))
	    (setf element-type (ldb (byte 5 0) identifier-octet)))
	(let ((first-length-octet (fast-io:fast-read-byte octet-stream)))
	  (cond ((zerop (ldb (byte 1 7) first-length-octet))
		 ;; First bit is 0, length is in short form
		 (setf element-length first-length-octet))
		(t
		 ;; First bit is 1, length is in long form-the first octet states how many
		 ;; octets the actual length occupies
		 (let* ((length-octets-length (ldb (byte 7 0) first-length-octet))
			(length-octets (fast-io:make-octet-vector length-octets-length)))
		   (fast-io:fast-read-sequence length-octets octet-stream)
		   (setf element-length (octets-to-integer length-octets))))))
	(values element-type
		;; Skip the first octet of an integer if it is 0
		(let ((contents (fast-io:make-octet-vector element-length)))
		  (fast-io:fast-read-sequence contents octet-stream)
		  (if (eql mode :deserialized)
		      (case element-type
			(:boolean
			 (plusp (aref contents 0)))
			(:integer
			 (octets-to-integer contents
					    :start (if (zerop (aref contents 0)) 1 0)))
			(:oid
			 (decode-oid contents))
			(:utf8-string
			 (handler-case
			     (babel:octets-to-string contents :encoding :utf-8)
			   (babel:character-decoding-error ()
			     (error 'asn.1-decoding-error
				    :text "Error decoding UTF8String"))))
			(:sequence
			 (asn-sequence-to-list contents))
			(:ia5-string;; Basically ASCII 0-127
			 (handler-case
			     (babel:octets-to-string contents :encoding :ascii)
			   (babel:character-decoding-error ()
			     (error 'asn.1-decoding-error
				    :text "Error decoding ia5String"))))
			(:utc-time;;Ascii-encoded string
			 (handler-case
			     (babel:octets-to-string contents :encoding :ascii)
			   (babel:character-decoding-error ()
			     (error 'asn.1-decoding-error
				    :text "Error decoding UTCTime"))))
			(:generalized-time;;Ascii-encoded string
			 (handler-case
			     (babel:octets-to-string contents :encoding :ascii)
			   (babel:character-decoding-error ()
			     (error 'asn.1-decoding-error
				    :text "Error decoding GeneralizedTime"))))
			(:visible-string;;Ascii-compatible 32-126
			 (handler-case
			     (babel:octets-to-string contents :encoding :ascii)
			   (babel:character-decoding-error ()
			     (error 'asn.1-decoding-error
				    :text "Error decoding VisibleString"))))
			(:printable-string;;Ascii-compatible 32-122
			 (handler-case
			     (babel:octets-to-string contents :encoding :ascii)
			   (babel:character-decoding-error ()
			     (error 'asn.1-decoding-error
				    :text "Error decoding printableString"))))
			(:bmp-string;;UCS-2
			 (handler-case
			     (babel:octets-to-string contents :encoding :ucs-2)
			   (babel:character-decoding-error ()
			     (error 'asn.1-decoding-error :text "Error decoding BMPString"))))
			;; NumericString: 5-bit encoding 32-57
			(otherwise contents))
		      contents))
		class constructedp))
    (end-of-file nil
      (error 'asn.1-decoding-error :text "Premature EOF"))))

(defun parse-der (obj &key (start 0) (mode :deserialized))
  "Serialized mode returns the plain contents octets, deserialized mode deserializes the contents octets. Octet strings and Bit Strings are not deserialized"
  (typecase obj
    ((simple-array (unsigned-byte 8) *)
     (fast-io:with-fast-input (octet-stream obj nil start)
       (from-stream-parse-der octet-stream :mode mode)))
    (otherwise
     (from-stream-parse-der obj :mode mode))))

(defun asn-sequence-to-list (vec &key (mode :deserialized))
  "Given an asn sequence, return a list of the raw der elements"
  (handler-case
      (fast-io:with-fast-input (octet-stream vec)
	(loop while (< (fast-io:buffer-position octet-stream) (length vec))
	   collecting (multiple-value-list (parse-der octet-stream :mode mode))))
    (end-of-file nil
      (error 'asn.1-decoding-error :text "Premature EOF"))))

(defun decode-oid (vec)
  "Decode an OID into a list of integers"
  (let (ints vlqs)
    (setf ints (multiple-value-list (floor (aref vec 0) 40)))
    (setf vlqs
	  (loop
	     with offset = 1
	     while (and (< offset (length vec))
			(position-if (lambda (x)
				       (zerop (ldb (byte 1 7) x))) vec :start offset))
	     for delimiter = (1+ (position-if (lambda (x)
						(zerop (ldb (byte 1 7) x))) vec
						:start offset))
	     then (1+ (position-if (lambda (x)
				     (zerop (ldb (byte 1 7) x))) vec :start offset))
	     collecting (subseq vec offset delimiter)
	     do (setf offset delimiter)))
    (append ints (loop
		    for vlq in vlqs collecting
		      (loop
			 for octet across vlq
			 with int = 0
			 for pos = (- (* (length vlq) 7) 7) then (decf pos 7)
			 do (setf (ldb (byte 7 pos) int) (ldb (byte 7 0) octet))
			 finally (return int))))))


(defun integer-to-vlq (n)
  (let* ((nlen (integer-length n))
	 (slides (ceiling nlen 7))
	 (octets (fast-io:make-octet-vector slides)))
    (loop
       for octet-index from (1- slides) downto 0
       for npos from 0 by 7
       do
	 (setf (aref octets octet-index)
	       (if (= octet-index (1- slides))
		   (ldb (byte 7 npos) n)
		   (logior 128 (ldb (byte 7 npos) n)))))
    octets))

(defun encode-oid (nums)
  (fast-io:with-fast-output (out)
    (fast-io:fast-write-byte (+ (* 40 (first nums))
				(second nums)) out)
    (loop
       for num in (cddr nums) do
	 (if (> num 127)
	     (fast-io:fast-write-sequence (integer-to-vlq num) out)
	     (fast-io:fast-write-byte num out)))))

(defun asn-serialize (obj type &key (class :universal))
  (let ((primitivep t))
    (case type
      (:integer
       (setf obj (integer-to-octets obj))
       (setf type 2))
      (:sequence
       (setf type 16)
       (setf primitivep nil))
      (:oid
       (setf obj (encode-oid obj))
       (setf type 6))
      (:octet-string
       (setf type 4))
      (:null
       (return-from asn-serialize (fast-io:octets-from #(#x05 #x00))))
      ;; 
      )
    (let ((identifier-octet #x00)
	  (len (length obj)))
      (fast-io:with-fast-output (out)
	(setf (ldb (byte 2 6) identifier-octet)
	      (ecase class
		(:universal 0)
		(:application 1)
		(:context-specific 2)
		(:private 3)))
	(or primitivep
	    (setf (ldb (byte 1 5) identifier-octet) 1))
	(setf (ldb (byte 5 0) identifier-octet) type)
	(fast-io:fast-write-byte identifier-octet out)
	(cond ((> len 127)
	       (fast-io:fast-write-byte
		(logior #b10000000 (bytes-in-int len)) out)
	       (fast-io:fast-write-sequence (integer-to-octets len) out))
	      (t
	       (fast-io:fast-write-byte len out)))
	(fast-io:fast-write-sequence obj out)))))
	   
(defun create-asn-sequence (&rest coll)
  (asn-serialize
   (fast-io:with-fast-output (out)
     (loop for el in coll do
	  (fast-io:fast-write-sequence
	   (apply #'asn-serialize el) out)))
   :sequence))
