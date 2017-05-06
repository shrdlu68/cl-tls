(in-package :cl-tls)

(defparameter *version* 1)
(defparameter *log-level* 1)
(defparameter *debug-stream* *error-output*)

(defconstant +change-cipher-spec+ 20)
(defconstant +alert+ 21)
(defconstant +handshake+ 22)
(defconstant +application-data+ 23)

(defconstant +hello-request+ 0)
(defconstant +client-hello+ 1)
(defconstant +server-hello+ 2)
(defconstant +certificate+ 11)
(defconstant +server-key-exchange+ 12)
(defconstant +certificate-request+ 13)
(defconstant +server-hello-done+ 14)
(defconstant +certificate-verify+ 15)
(defconstant +client-key-exchange+ 16)
(defconstant +finished+ 20)

(defparameter *max-fragment-length* (expt 2 14))

(defparameter *max-certificate-chain-length* 20)

(define-condition exception (error)
  ((log :initarg :log :accessor log-info)
   (alert :initarg :alert :accessor alert)))

(define-condition tls-stream-error (stream-error)
  ())

(define-condition tls-error (error)
  ((text :initarg :text :accessor text)))

(define-condition tunnel-closed (error)
  ())

(defclass hello-extensions ()
  ((host-name :initarg :host-name
	      :initform nil
	      :accessor host-name)
   (max-fragment-length :initarg :max-fragment-length
			:initform nil
			:accessor max-fragment-length)
   (client-certificate-url :initarg :client-certificate-url
			   :initform nil
			   :accessor client-certificate-url)
   (supported-signature-algorithms :initarg :supported-signature-algorithms
				   :initform nil
				   :accessor supported-signature-algorithms)))

(defclass session ()
  ((role :initarg :role)
   (version :initform (make-octet-vector :initial-contents #(3 3))
	    :initarg :version)
   (hello-version :initform (make-octet-vector :initial-contents #(3 3))
		  :initarg :version)
   (resumable :initform nil
	      :initarg :resumable)
   (ciphers :initarg :ciphers)
   (state :initform :connecting) 	;Connection state of the TLS stream
   (handshake-stage :initform nil)	;Handshake stage
   (certificate-requested :initform nil)
   (remote-certificate-type :initform nil)
   (cipher-suite :initform nil)
   (session-id :initform nil)
   (sequence-number-write :initform 0)
   (sequence-number-read :initform 0)
   (session-read-state :initform :null)
   (session-write-state :initform :null)
   (client-random :initform nil)
   (server-random  :initform nil)
   (master-secret  :initform nil)
   (key-exchange-method  :initform nil)
   (authentication-method  :initform nil)
   (encryption-algorithm  :initform nil)
   (cipher-mode  :initform nil)
   (mac-algorithm  :initform nil)
   (block-size  :initform nil)
   (cipher-type  :initform nil)
   (requested-cert-type :initform nil)
   (supported-sig-algos :initform nil)
   (dh-params :initform nil)
   (dh-Y :initform nil)
   (dhe-private-key :initform nil)
   (extensions-data :initform (make-instance 'hello-extensions))
   ;; Key size
   (mac-key-length :initform 0)
   (enc-key-length :initform 0)
   (record-iv-length :initform 0)
   ;; Keying material
   (key_block :initform nil)
   (client-write-mac-key :initform nil)
   (server-write-mac-key :initform nil)
   (client-write-key :initform nil)
   (server-write-key :initform nil)
   (client-write-iv :initform nil)
   (server-write-iv :initform nil)
   (peer-dns-name :initform nil
		  :initarg :peer-dns-name)
   (peer-ip-addresses :initform nil
		      :initarg :peer-ip-addresses)
   (certificate :initarg :certificate
		:initform nil)
   (ca-certificates :initarg :ca-certificates
		    :initform nil)
   (io-stream :initform nil
	      :initarg :io-stream)
   (input-stream :initform nil
		 :initarg :input-stream)
   (output-stream :initform nil
		  :initarg :output-stream)
   (pub-key :accessor pub-key
	    :initform nil)
   (priv-key :initarg :private-key
	     :initform nil)
   (encrypting-cipher-object :initform nil)
   (decrypting-cipher-object :initform nil)
   (pre-master-secret :accessor pre-master-secret
		      :initform nil)
   (handshake-messages :accessor handshake-messages
		       :initform (fast-io:make-octet-vector 0))))

(defclass shared-session-slots ()
  ((role :Initform :server
	 :initarg :role
	 :allocation :class)
   (certificate  :initform nil
		 :initarg :certificate
		 :allocation :class)
   (ca-certificates :initform nil
		    :initarg :ca-certificates
		    :allocation :class)
   (resumable :initform nil
	      :initarg :resumable
	      :allocation :class)
   (ciphers :initarg :ciphers
	    :allocation :class)
   (pub-key :initform nil
	    :allocation :class)
   (priv-key :initform nil
	     :initarg :private-key
	     :allocation :class)
   (dh-params :initform nil
	      :initarg :dh-params
	      :allocation :class)
   (version :initform (fast-io:octets-from #(3 3))
	    :initarg :version
	    :allocation :class)
   (authenticate-client-p :initform nil
			  :initarg :authenticate-client-p
			  :allocation :class)
   (require-authentication-p :initform nil
			     :initarg :require-authentication-p
			     :allocation :class)))

(defclass server-session (shared-session-slots session)
  ())

(defclass client-session (session)
  ((role :initform :client)))

(defun get-session-id ()
  (get-random-octets 4))

(defgeneric send-record (session content-type payload &key))

(defmethod send-record ((session session) content-type payload
			&key (start 0) (end (length payload)))
  (handler-case
      (with-slots (version sequence-number-write io-stream output-stream) session
	(let* ((stream (or io-stream output-stream))
	       (payload-length (- end start)))
	  (write-byte content-type stream)
	  (write-sequence version stream)
	  (write-sequence (integer-to-octets payload-length 2) stream)
	  (write-sequence payload stream :start start :end end)
	  (finish-output stream))
	(incf sequence-number-write))
    (stream-error ()
      (error 'tls-stream-error))))

(defgeneric encrypt (session plaintext))

(defmethod encrypt ((session session) plaintext)
  (with-slots (role encryption-algorithm client-write-key server-write-key
	       record-iv-length cipher-mode encrypting-cipher-object)
      session
    (case encryption-algorithm
      (:aes
       (ironclad:encrypt-in-place
	(ironclad:make-cipher :aes
			      :key endpoint-encryption-key
			      :mode cipher-mode
			      :initialization-vector (subseq plaintext 0 record-iv-length))
	plaintext :start record-iv-length))
      (:3des
       (ironclad:encrypt-in-place
	(ironclad:make-cipher
	 :3des
	 :key endpoint-encryption-key
	 :mode cipher-mode
	 :initialization-vector (subseq plaintext 0 record-iv-length))
	plaintext :start record-iv-length))
      (:rc4
       (ironclad:encrypt-in-place encrypting-cipher-object plaintext)))))

(defgeneric decrypt (session ciphertext))

(defmethod decrypt ((session session) ciphertext)
  (with-slots (role encryption-algorithm client-write-key server-write-key
	       record-iv-length cipher-mode decrypting-cipher-object)
      session
    (case encryption-algorithm
      (:aes
       (ironclad:decrypt-in-place
	(ironclad:make-cipher
	 :aes
	 :key endpoint-decryption-key
	 :mode cipher-mode
	 :initialization-vector (subseq ciphertext 0 record-iv-length))
	ciphertext :start record-iv-length))
      (:3des
       (ironclad:decrypt-in-place
	(ironclad:make-cipher
	 :3des
	 :key endpoint-decryption-key
	 :mode cipher-mode
	 :initialization-vector (subseq ciphertext 0 record-iv-length))
	ciphertext :start record-iv-length))
      (:rc4
       (ironclad:decrypt-in-place decrypting-cipher-object ciphertext)))))

(define-symbol-macro endpoint-mac-encryption-key
    (if (eql role :client)
	client-write-mac-key
	server-write-mac-key))

(define-symbol-macro endpoint-mac-decryption-key
    (if (eql role :client)
	server-write-mac-key
	client-write-mac-key))

(defun calculate-mac (session content-type message)
  (with-slots
	(role version mac-algorithm client-write-mac-key
	 server-write-mac-key sequence-number-write) session
    (let ((hmac (ironclad:make-hmac endpoint-mac-encryption-key mac-algorithm))
	  (mac-seed (make-array (+ 8 1 2 2 (length message)) :element-type 'octet)))
      ;; seq_num
      (replace mac-seed (integer-to-octets sequence-number-write 8))
      ;; TLSCompressed.type
      (setf (aref mac-seed 8) content-type)
      ;; TLSCompressed.version
      (replace mac-seed version :start1 9)
      ;; TLSCompressed.length
      (replace mac-seed (integer-to-octets (length message) 2) :start1 11)
      ;; TLSCompressed.fragment
      (replace mac-seed message :start1 13)
      (ironclad:update-hmac hmac mac-seed)
      (ironclad:hmac-digest hmac))))

(defun calculate-verification-mac (session content-type message)
  (with-slots
	(role version mac-algorithm client-write-mac-key
	 server-write-mac-key sequence-number-read) session
    (let ((hmac (ironclad:make-hmac endpoint-mac-decryption-key mac-algorithm))
	  (mac-seed (make-array (+ 8 1 2 2 (length message)) :element-type 'octet))
	  mac)
      ;; seq_num
      (replace mac-seed (integer-to-octets sequence-number-read 8))
      ;; TLSCompressed.type
      (setf (aref mac-seed 8) content-type)
      ;; TLSCompressed.version
      (replace mac-seed version :start1 9)
      ;; TLSCompressed.length
      (replace mac-seed (integer-to-octets (length message) 2) :start1 11)
      ;; TLSCompressed.fragment
      (replace mac-seed message :start1 13)
      (ironclad:update-hmac hmac mac-seed)
      (setf mac (ironclad:hmac-digest hmac))
      mac
      )))

(defgeneric ciphertext-to-compressed (session content-type ciphertext))

(defmethod ciphertext-to-compressed ((session session) content-type ciphertext)
  (with-slots
	(role cipher-type encryption-algorithm block-size mac-key-length
	 record-iv-length client-write-mac-key server-write-mac-key
	 mac-algorithm sequence-number-write version)
      session
    (decrypt session ciphertext)
    (case cipher-type
      (:block
	  ;; Length checks
	  (when (< (length ciphertext) (+ record-iv-length mac-key-length 1))
	    (error 'exception
		   :log "Incorrect encoding of GenericBlockCipher struct"
		   :alert :decode-error))
	(let* ((padding-length (aref ciphertext (1- (length ciphertext))))
	       (content-length
		 (- (length ciphertext)
		    (+ record-iv-length mac-key-length padding-length 1)))
	       verify-mac
	       content)
	  ;; Length checks, again
	  (unless (plusp content-length)
	    (error 'exception
		   :log "Invalid padding length in GenericBlockCipher struct"
		   :alert :decode-error))
	  (setf content (subseq ciphertext record-iv-length
				(+ record-iv-length content-length)))
	  (setf verify-mac (calculate-verification-mac session content-type content))
	  (unless (timing-independent-compare
		   verify-mac
		   (subseq ciphertext (+ record-iv-length content-length)
			   (+ record-iv-length content-length mac-key-length)))
	    (error 'exception
		   :log "Invalid MAC in GenericBlockCipher struct"
		   :alert :bad-record-mac))
	  content))
      (:stream
       (unless (> (length ciphertext) mac-key-length)
	 (error 'exception
		:log "Incorrect encoding of GenericStreamCipher struct"
		:alert :decode-error))
       (let* ((content-length (- (length ciphertext) mac-key-length))
	      (content (subseq ciphertext 0 content-length))
	      (verify-mac (calculate-verification-mac session content-type content)))
	 (unless (timing-independent-compare verify-mac
					     (subseq ciphertext content-length))
	   (error 'exception
		  :log "Invalid MAC in GenericStreamCipher struct"
		  :alert :bad-record-mac))
	 content)))))

(defun encrypt-and-send (session content-type content
			 &key (start 0) (end (length content)))
  (with-slots
	(cipher-type encryption-algorithm block-size mac-key-length record-iv-length
	 session-write-mac-key mac-algorithm sequence-number-write version)
      session
    (case cipher-type
      (:block
	  ;; The padding_length is exclusive of the padding_length itself
	  (let* ((content-length (- end start))
		 (padding-length (- block-size
				    (mod (+ content-length mac-key-length 1)
					 block-size)))
		 (generic-block-cipher (make-array (+ record-iv-length content-length
						      mac-key-length
						      padding-length 1)
						   :element-type 'octet)))
	    ;; Write the IV
	    (get-random-octets record-iv-length
			       (subseq generic-block-cipher 0 record-iv-length))
	    ;; Content
	    (replace generic-block-cipher content
		     :start1 record-iv-length
		     :start2 start :end2 end)
	    ;; Calculate the MAC
	    (replace generic-block-cipher
		     (calculate-mac session content-type content)
		     :start1 (+ record-iv-length content-length))
	    ;; Pad
	    (fill generic-block-cipher padding-length
		  :start (+ record-iv-length content-length mac-key-length))
	    ;; Encrypt the block in-place
	    (encrypt session generic-block-cipher)
	    ;; Send
	    (send-record session content-type generic-block-cipher)))
      (:stream
       (let* ((content-length (- end start))
	      (generic-stream-cipher
		(make-array (+ content-length mac-key-length) :element-type 'octet)))
	 (replace generic-stream-cipher content :start2 start :end2 end)
	 (replace generic-stream-cipher (calculate-mac session content-type content)
		  :start1 content-length)
	 ;; Encrypt the block in-place
	 (encrypt session generic-stream-cipher)
	 ;; Send
	 (send-record session content-type generic-stream-cipher))))))

(defgeneric send (session content-type payload))

(defmethod send ((session session) content-type payload)
  "Fragment -> (optionally) Compress -> Apply MAC -> Encrypt -> Transmit"
  (with-slots (role session-write-state handshake-messages
	       cipher-type mac-key-length record-iv-length) session
    ;; Append to handshake messages for verified_data--except hello requests and finished messages
    (when (and (= content-type +handshake+)
	       (/= (aref payload 0) +finished+)
	       (/= (aref payload 0) +hello-request+))
      (setf handshake-messages
	    (cat-vectors handshake-messages payload)))
    ;; Fragment and send
    (let ((max-data-length
	    (if (eql :encrypted session-write-state)
		(case cipher-type
		  (:block
		      (- *max-fragment-length*
			 (+ mac-key-length record-iv-length 9)))
		  (:stream
		   (- *max-fragment-length* mac-key-length)))
		*max-fragment-length*))
	  (data-length (length payload)))
      (loop
	for index from 0 by max-data-length
	while (< index data-length)
	do
	   ;; Encrypt and transmit
	   (if (eql :encrypted session-write-state)
	       (encrypt-and-send session content-type payload
				 :start index
				 :end (min (+ index max-data-length)
					   data-length))
	       (send-record session content-type payload
			    :start index :end (min (+ index max-data-length)
						   data-length)))))))

(defgeneric send-handshake (session handshake-type))

(defun add-handshake-header (handshake-type buffer)
  (fast-io:with-fast-output (out)
    (fast-io:fast-write-byte handshake-type out)
    (fast-io:fast-write-sequence (integer-to-octets (length buffer) 3) out)
    (fast-io:fast-write-sequence buffer out)))

(defmethod send-handshake ((session session) (handshake-type (eql :server-hello)))
  (let ((msg
	  (fast-io:with-fast-output (msg)
	    (with-slots (resumable version cipher-suite server-random) session
	      (setf server-random (make-array 32 :element-type 'octet))
	      (setf (subseq server-random 0 4) (integer-to-octets (gmt-unix-time) 4))
	      (setf (subseq server-random 4) (get-random-octets 28))
	      (fast-io:fast-write-sequence version msg)
	      (fast-io:fast-write-sequence server-random msg)
	      ;; TODO: No session-id for now
	      (fast-io:fast-write-byte 0 msg)
	      ;; Cipher suite
	      (fast-io:fast-write-sequence cipher-suite msg)
	      ;; No compression
	      (fast-io:fast-write-byte 0 msg)
	      ;; TODO: No extensions for now
	      ))))
    (send
     session
     +handshake+
     (add-handshake-header +server-hello+ msg))))

(defmethod send-handshake ((session session) (handshake-type (eql :certificate)))
  (with-slots (certificate) session
    (send
     session
     +handshake+
     (fast-io:with-fast-output (msg)
       ;; Handshake type
       (fast-io:fast-write-byte +certificate+ msg)
       ;; Handshake length
       (fast-io:fast-write-sequence
	(Integer-to-octets (+ 3
			      (* 3 (length certificate))
			      (loop for cert in certificate summing (length cert))) 3)
	msg)
       ;; Certificates length
       (fast-io:fast-write-sequence
	(Integer-to-octets (+ (* 3 (length certificate))
			      (loop for cert in certificate summing (length cert))) 3)
	msg)
       (loop for cert in certificate do
	 ;; Certificate length
	 (fast-io:fast-write-sequence (integer-to-octets (length cert) 3) msg)
	 ;; Certificate
	 (fast-io:fast-write-sequence cert msg))))))

(defmethod send-handshake ((session session) (handshake-type (eql :client-certificate)))
  (send-handshake session :certificate))

(defmethod send-handshake ((session session) (handshake-type (eql :certificate-verify)))
  (send
   session
   +handshake+
   (add-handshake-header
    +certificate-verify+
    (with-slots (handshake-messages) session
      (digitally-sign session handshake-messages)))))

(defparameter *certificate-request-msg*
  (let* ((client-certificate-types
	   (make-octet-vector :initial-contents #(#x01 #x02 #x03 #x04)))
	 (md5 #x01) (sha1 #x02) (sha224 #x03) (sha256 #x04) (sha384 #x05)
	 (sha512 #x06) (rsa #x01) (dsa #x02) ;; (ecdsa #x03)
	 (supported-algs
	   (make-octet-vector
	    :initial-contents
	    (vector
	     sha512 rsa sha384 rsa sha256 rsa sha224 rsa sha1 rsa md5 rsa
	     sha512 dsa sha384 dsa sha256 dsa sha224 dsa sha1 dsa md5 dsa
	     ;; sha512 ecdsa sha384 ecdsa sha256 ecdsa sha224 ecdsa sha1 ecdsa md5 ecdsa
	     ))))
    (fast-io:with-fast-output (msg)
      ;; Handshake type
      (fast-io:fast-write-byte +certificate-request+ msg)
      ;; Length
      (fast-io:fast-write-sequence
       (integer-to-octets (+ 1 (length client-certificate-types)
			     2 (length supported-algs)
			     2)
			  3)
       msg)
      (fast-io:fast-write-byte (length client-certificate-types) msg)
      (fast-io:fast-write-sequence client-certificate-types msg)
      (fast-io:writeu16-be (length supported-algs) msg)
      (fast-io:fast-write-sequence supported-algs msg)
      (fast-io:writeu16-be 0 msg))))

(defmethod send-handshake ((session session) (handshake-type (eql :certificate-request)))
  (send
   session
   +handshake+
   *certificate-request-msg*))

(defmethod send-handshake ((session session) (handshake-type (eql :server-key-exchange)))
  (with-slots (authentication-method
	       key-exchange-method pre-master-secret
	       client-random server-random dhe-private-key
	       priv-key dh-params) session
    (let* ((server-dh-params
	     (fast-io:with-fast-output (out)
	       (with-slots (p g) dh-params
		 (multiple-value-bind (x y)
		     (make-dh-key-pair dh-params
				       (when (eql key-exchange-method :dh)
					 priv-key))
		   ;; Save the private DH value
		   (or (and (eql key-exchange-method :dh)
			    priv-key)
		       (setf dhe-private-key x))
		   (let ((dh_p (integer-to-octets p))
			 (dh_g (integer-to-octets g))
			 (dh_Ys (integer-to-octets y)))
		     (fast-io:writeu16-be (length dh_p) out)
		     (fast-io:fast-write-sequence dh_p out)
		     (fast-io:writeu16-be (length dh_g) out)
		     (fast-io:fast-write-sequence dh_g out)
		     (fast-io:writeu16-be (length dh_Ys) out)
		     (fast-io:fast-write-sequence dh_Ys out))))))
	   (msg
	     (fast-io:with-fast-output (out)
	       (cond
		 ((and (eql key-exchange-method :anon)
		       (eql authentication-method :dh))
		  (fast-io:fast-write-sequence server-dh-params out))
		 ((and (eql key-exchange-method :dhe)
		       (or (eql authentication-method :rsa)
			   (eql authentication-method :dsa)))
		  (fast-io:fast-write-sequence server-dh-params out)
		  (fast-io:fast-write-sequence
		   (sign-dh-params session server-dh-params) out))))))
      (send
       session
       +handshake+
       (add-handshake-header +server-key-exchange+ msg)))))

(defmethod send-handshake ((session session) (handshake-type (eql :server-hello-done)))
  (send
   session
   +handshake+
   (let ((msg (make-array 4 :element-type 'octet :initial-element 0)))
     (setf (aref msg 0) +server-hello-done+)
     msg)))

(defmethod send-handshake ((session session) (handshake-type (eql :finished)))
  (with-slots (role master-secret handshake-messages) session
    (let ((label (if (eql role :client) "client finished" "server finished"))
	  (msg (make-array 16 :element-type 'octet)))
      ;; Handshake type
      (setf (aref msg 0) +finished+)
      ;; Handshake length
      (replace msg (integer-to-octets 12 3) :start1 1)
      ;; Handshake contents
      (replace msg
	       (prf master-secret label
		    (ironclad:digest-sequence :sha256 handshake-messages) 12) :start1 4)
      ;; The server's finished will include this message
      (when (eql role :client)
        (setf handshake-messages
	      (cat-vectors handshake-messages msg)))
      (send session +handshake+ msg))))

(defmethod send-handshake ((session session) (handshake-type (eql :client-key-exchange)))
  (send
   session
   +handshake+
   (add-handshake-header
    +client-key-exchange+
    (with-slots
	  (key-exchange-method
	   pre-master-secret
	   hello-version pub-key dh-params dh-Y) session
      (cond
	((eql key-exchange-method :rsa)
	 (fast-io:with-fast-output (out)
	   (setf pre-master-secret (make-array 48 :element-type 'octet))
	   (replace pre-master-secret hello-version)
	   (setf (subseq pre-master-secret 2) (get-random-octets 46))
	   (let ((encrypted-premaster (rsa-encrypt pre-master-secret pub-key)))
	     (fast-io:writeu16-be (length encrypted-premaster) out)
	     (fast-io:fast-write-sequence encrypted-premaster out))))
	((eql key-exchange-method :dh)
	 (fast-io:make-octet-vector 0))
	((eql key-exchange-method :dhe)
	 (let* ((Y (multiple-value-bind (secret-exp public-value)
		       (make-dh-key-pair dh-params)
		     ;; Generate the DH secret, which is the PreMasterSecret
		     (setf pre-master-secret
			   (integer-to-octets
			    (compute-shared-secret dh-params secret-exp dh-Y)))
		     ;; Strip leading bytes that are zero from the pre-master value
		     (when (zerop (aref pre-master-secret 0))
		       (setf pre-master-secret
			     (subseq pre-master-secret
				     (position-if #'plusp pre-master-secret))))
		     (integer-to-octets public-value))))
	   (fast-io:with-fast-output (out)
	     ;; DH public value length
	     (fast-io:writeu16-be (length Y) out)
	     ;; Content - the dh public value
	     (fast-io:fast-write-sequence Y out)))))))))

(defgeneric handle-handshake (message session type))

(defmethod handle-handshake (buffer session (type (eql :client-key-exchange)))
  (with-slots
	(key-exchange-method
	 pre-master-secret priv-key dhe-private-key
	 hello-version dh-params dh-Y) session
    (cond
      ((eql key-exchange-method :rsa)
       (let ((R (get-random-octets 46))
	     (M (rsa-decrypt (subseq buffer 6) priv-key)))
	 (cond ((and M
		     (= 48 (length M)))
		(setf pre-master-secret
		      (cat-vectors hello-version (subseq M 2))))
	       (t
		(setf pre-master-secret
		      (cat-vectors hello-version R))))))
      ((or (eql key-exchange-method :dh)
           (eql key-exchange-method :dhe))
       (setf buffer (subseq buffer 4))
       (cond
	 ((= (length buffer) 2)
	  (or dh-Y
	      (error 'exception
		     :log "Invalid clientKeyExchange message"
		     :alert :handshake-failure))
	  )
	 ((> (length buffer) 2)
	  (setf pre-master-secret
		(integer-to-octets
		 (compute-shared-secret
		  dh-params (or (and (eql key-exchange-method :dh)
				     priv-key)
				dhe-private-key)
		  (octets-to-integer buffer :start 2)))))
	 (t
	  (error 'exception
		 :log "Malformed ClientKeyExchange message"
		 :alert :decode-error)))))))

(defmethod handle-handshake (buffer session (type (eql :certificate-verify)))
  (with-slots (handshake-messages) session
    (with-specification-map ((algorithm 2)
			     (signature (0 65535)))
      (subseq buffer 4)
      (error 'exception
	     :log "Malformed CertificateVerify"
	     :alert :decode-error)
      (or (verify-signed-data session handshake-messages algorithm signature)
	  (error 'exception
		 :log "Signature verification failed in certificateVerify"
		 :decrypt-error)))))

(defgeneric send-change-cipher-spec (session))

(defmethod send-change-cipher-spec (session)
  (with-slots (sequence-number-write session-write-state) session
    (send session +change-cipher-spec+
	  (fast-io:octets-from #(1)))
    (setf sequence-number-write 0)
    (setf session-write-state :encrypted)))

(defmethod send-handshake ((session session) (handshake-type (eql :client-hello)))
  (with-slots (version resumable client-random
	       session-id ciphers peer-dns-name) session
    (let ((msg (fast-io:with-fast-output (out)
		 (fast-io:fast-write-sequence version out)
		 ;; struct {
		 ;; uint32 gmt_unix_time;
		 ;; opaque random_bytes[28];
		 ;;          } Random;
		 (setf client-random (make-array 32 :element-type 'octet))
		 (setf (subseq client-random 0 4) (integer-to-octets (gmt-unix-time) 4))
		 (get-random-octets 28 (subseq client-random 4))
		 (fast-io:fast-write-sequence client-random out)
		 ;; opaque SessionID<0..32>;
		 (if resumable
		     (let ((session-id (get-session-id)))
		       (fast-io:fast-write-byte (length session-id) out)
		       (fast-io:fast-write-sequence session-id out))
		     (fast-io:fast-write-byte 0 out))
		 ;; uint8 CipherSuite[2]
		 ;; CipherSuite cipher_suites<2..2^16-2>;
		 (fast-io:fast-write-sequence
		  (integer-to-octets (length ciphers) 2) out)
		 (fast-io:fast-write-sequence ciphers out)
		 ;; CompressionMethod compression_methods<1..2^8-1>
		 ;; NULL compression
		 (fast-io:fast-write-sequence (fast-io:octets-from #(1 0)) out)
		 ;; Extension extensions<0..2^16-1>
		 (let* ((extensions
			  (fast-io:with-fast-output (ext)
			    ;; Create extensions here
			    ;; SNI
			    (when peer-dns-name
			      (fast-io:fast-write-sequence
			       (create-sni peer-dns-name) ext))
			    ;; CertificateStatusRequest
			    
			    ;; Other extensions
			    ))
			(ext-len (length extensions)))
		   (when (plusp ext-len)
		     (fast-io:fast-write-sequence
		      (integer-to-octets ext-len 2) out)
		     (fast-io:fast-write-sequence extensions out))))))
      (send session +handshake+
	    (add-handshake-header +client-hello+ msg)))))


(defun parse-cipher-suite (cipher-suite session)
  (with-slots (server-random key-exchange-method authentication-method encryption-algorithm
	       cipher-mode mac-algorithm block-size cipher-type mac-key-length
	       enc-key-length record-iv-length) session
    (cond
      ;; Define the key exchange method
      ((find cipher-suite +rsa-key-exchange-suites+ :test #'equalp)
       (setf key-exchange-method :rsa))
      ((find cipher-suite +dh-key-exchange-suites+ :test #'equalp)
       (setf key-exchange-method :dh))
      ((find cipher-suite +dhe-key-exchange-suites+ :test #'equalp)
       (setf key-exchange-method :dhe)))
    ;; Define the authentication method
    (cond
      ((find cipher-suite +rsa-authentication-suites+ :test #'equalp)
       (setf authentication-method :rsa))
      ((find cipher-suite +dss-authentication-suites+ :test #'equalp)
       (setf authentication-method :dsa))
      ((find cipher-suite +anon-authentication-suites+ :test #'equalp)
       (setf authentication-method :anon)))
    ;; Define the bulk encryption algorithm
    (cond
      ((find cipher-suite +rc4-encryption-suites+ :test #'equalp)
       (setf encryption-algorithm :rc4)
       (setf enc-key-length 16)
       (setf cipher-type :stream))
      ((find cipher-suite +3des-encryption-suites+ :test #'equalp)
       (setf encryption-algorithm :3des)
       (setf enc-key-length 24)
       (setf record-iv-length 8)
       (setf block-size 8)
       (setf cipher-type :block))
      ((find cipher-suite +aes-encryption-suites+ :test #'equalp)
       (setf encryption-algorithm :aes)
       (setf cipher-type :block)
       (setf record-iv-length 16)
       (setf block-size 16)
       (cond ((find cipher-suite +aes-128-ciphers+ :test #'equalp)
	      (setf enc-key-length 16))
	     ((find cipher-suite +aes-256-ciphers+ :test #'equalp)
	      (setf enc-key-length 32)))))
    (cond
      ((find cipher-suite +cbc-mode-ciphers+ :test #'equalp)
       (setf cipher-mode :cbc)))
    ;; Mac algorithm
    (cond
      ((find cipher-suite +md5-ciphers+ :test #'equalp)
       (setf mac-algorithm :md5)
       (setf mac-key-length 16))
      ((find cipher-suite +sha1-ciphers+ :test #'equalp)
       (setf mac-algorithm :sha1)
       (setf mac-key-length 20))
      ((find cipher-suite +sha256-ciphers+ :test #'equalp)
       (setf mac-algorithm :sha256)
       (setf mac-key-length 32)))))

(defun cipher-suite-supported-p (cs session)
  (with-slots (ciphers) session
    (loop
      with cs0 = (aref cs 0)
      with cs1 = (aref cs 1)
      with len = (length ciphers)
      for a from 0 below len by 2
      for b from 1 below len by 2
      when (and (= cs0 (aref ciphers a))
		(= cs1 (aref ciphers b)))
	do (return t))))

(defmethod handle-handshake (buffer session (type (eql :client-hello)))
  (with-slots (client-random resumable session-id cipher-suite hello-version) session
    (with-specification-map ((version 2)
			     (random 32)
			     (session_id (0 32))
			     (cipher-suites (2 65534))
			     (compression-methods (1 255))
			     (extensions 0 65535))
      (subseq buffer 4)
      (error 'exception
	     :log "Malformed ClientHello"
	     :alert :decode-error)
      (setf hello-version (make-octet-vector :initial-contents version))
      (setf client-random random)
      (unless (evenp (length cipher-suites))
	(error 'exception
	       :log "Malformed ClientHello"
	       :alert :decode-error))
      (let ((cs (loop for i from 0 to (- (length cipher-suites) 2) by 2
		      for suite = (subseq cipher-suites i (+ 2 i))
		      when (cipher-suite-supported-p suite session)
			return suite)))
	(unless cs
	  (error 'exception
		 :log "Handshake failure: Client's ciphersuites are not supported/enabled."
		 :alert :handshake-failure))
	(setf cipher-suite cs)
	(parse-cipher-suite cs session))
      (when resumable
	(setf session-id (subseq session_id 0)))
      ;; Ignore compression methods field
      compression-methods
      
      (when (plusp (length extensions))
	(fast-io:with-fast-input
	    (ext extensions)
	  (handler-case
	      (loop
		for extension-type = (fast-io:readu16-be ext)
		for extension-data-length = (fast-io:readu16-be ext)
		for extension-data = (fast-io:make-octet-vector extension-data-length)
		while (< (fast-io:buffer-position ext) (length extensions))
		do
		   (fast-io:fast-read-sequence extension-data ext)
		   (case extension-type
		     (13 (parse-extension session extension-data :signature-algorithms))
		     (0 (parse-extension session extension-data :server-name))
		     (1 (parse-extension session extension-data :max-fragment-length))
		     (2 (parse-extension session extension-data :client-certificate-url))
		     (3 (parse-extension session extension-data :trusted-ca-keys))
		     (4 (parse-extension session extension-data :truncated-hmac))
		     (5 (parse-extension session extension-data :status-request))
		     (otherwise
		      (format t "Unknown extension type")
		      (error 'exception
			     :log "Unknown extension type"
			     :alert :illegal-parameter))))
	    (end-of-file nil
	      (error 'exception
		     :log "Invalid encoding in ClientHello"
		     :alert :decode-error))))))))

(defmethod handle-handshake (buffer session (type (eql :server-key-exchange)))
  (with-slots (key-exchange-method authentication-method
	       client-random pub-key server-random dh-params dh-Y) session
    (cond ((and (eql key-exchange-method :dh)
		(eql authentication-method :anon))
	   (with-specification-map ((dh_p  (1 65535))
				    (dh_g  (1 65535))
				    (dh_Ys  (1 65535)))
	     (subseq buffer 4)
	     (error 'exception
		    :log "Malformed ServerDHParams in ServerKeyExchange"
		    :alert :decode-error)
	     (setf dh-params (generate-dh-params
			      :p (octets-to-integer dh_p)
			      :g (octets-to-integer dh_g)))
	     (setf dh-Y (octets-to-integer dh_Ys))))
	  ((and (eql key-exchange-method :dhe)
		(find authentication-method '(:rsa :dsa)))
	   (with-specification-map ((dh_p  (1 65535))
				    (dh_g  (1 65535))
				    (dh_Ys  (1 65535))
				    (algorithm 2)
				    (signature (0 65535)))
	     
	     (subseq buffer 4)
	     (error 'exception
		    :log "Malformed ServerDHParams in ServerKeyExchange"
		    :alert :decode-error)
	     ;; Verify the signature
	     (unless (verify-signed-params
		      session
		      (cat-vectors (integer-to-octets (length dh_p) 2)
				   dh_p
				   (integer-to-octets (length dh_g) 2)
				   dh_g
				   (integer-to-octets (length dh_Ys) 2)
				   dh_Ys)
		      algorithm signature)
	       (error 'exception
		      :log "Signature verification of ServerDHParams failed"
		      :alert :decrypt-error))
	     (setf dh-params (generate-dh-params
			      :p (octets-to-integer dh_p)
			      :g (octets-to-integer dh_g)))
	     (setf dh-Y (octets-to-integer dh_Ys))
	     (finish-output)))
	  (t
	   (error 'exception
		  :log "Unexpected handshake message: serverKeyExchange"
		  :alert :unexpected-message)))))

(defmethod handle-handshake (buffer session (type (eql :finished)))
  (with-slots (role master-secret handshake-messages state) session
    (let* ((label (if (eql role :client) "server finished" "client finished"))
	   (verify-data
	     (prf master-secret label
		  (ironclad:digest-sequence :sha256 handshake-messages) 12)))
      (unless (timing-independent-compare verify-data (subseq buffer 4))
	(error 'exception
	       :log "Invalid verify-data in finished message"
	       :alert :decrypt-error))
      ;; Success, connection is now open
      (setf state :open)
      ;; Servers append the client's finished to the handshake-messages
      (when (eql role :server)
        (setf handshake-messages
	      (cat-vectors handshake-messages buffer))))))

(defmethod handle-handshake (buffer session (type (eql :certificate-request)))
  (with-slots (handshake-stage
	       certificate-requested requested-cert-type supported-sig-algos) session
    (setf certificate-requested t)
    (with-specification-map ((certificate-types (1 255))
			     (supported-signature-algorithms (0 65535))
			     (certificate-authorities (0 65535)))
      (subseq buffer 4)
      (error 'exception
	     :log "Malformed CertificateRequest message"
	     :alert :decode-error)
      (setf requested-cert-type
	    (loop
	      for i across certificate-types
	      collecting
	      (case i
		(1 :rsa-sign) (2 :dss-sign) (3 :rsa-fixed-dh)
		(4 :dss-fixed-dh) (64 :ecdsa-sign) (65 :rsa-fixed-ecdh)
		(66 :ecds-fixed-ecdh)
		(otherwise (error 'exception
				  :log "Unknown/unsupported ClientCertificateType"
				  :alert :illegal-parameter)))))
      (unless (evenp (length supported-signature-algorithms))
	(error 'exception
	       :log "Invalid encoding in CertificateRequest message"
	       :alert :decode-error))
      (setf supported-sig-algos
	    (loop for i from 0 to (1- (length supported-signature-algorithms)) by 2
		  collecting
		  (list
		   (case (aref supported-signature-algorithms i)
		     (1 :md5) (2 :sha1) (3 :sha224)
		     (4 :sha256) (5 :sha384) (6 :sha512)
		     (otherwise (error 'exception
				       :log "Unknown/unsupported hash algorithm in SupportedSignatureAlgorithms in CertificateRequest"
				       :alert :illegal-parameter)))
		   (case (aref supported-signature-algorithms (1+ i))
		     (1 :rsa) (2 :dsa) (3 :ecdsa)
		     (otherwise (error 'exception
				       :log "Unknown/unsupported signature algorithm in SupportedSignatureAlgorithms in CertificateRequest"
				       :alert :illegal-parameter))))))
      (when certificate-authorities
	;; TODO parse this field
	(format t "~&Auth: ~S~%" certificate-authorities)))))

(defmethod handle-handshake (buffer session (type (eql :server-hello-done)))
  ;; Nothing useful here
  buffer session)

(defmethod handle-handshake (buffer session (type (eql :certificate)))
  (with-slots (role require-authentication-p) session
    (and (eql role :server)
	 require-authentication-p
	 (< (length buffer) 8)
	 (error 'exception
		:log "Client sent an empty certificate."
		:alert :handshake-failure)))
  (unless (> (length buffer) 8)
    (error 'exception
	   :log "Malformed certificate message"
	   :alert :decode-error))
  ;; Convert each certificate to an x509 hash-table
  (let* ((raw-certificates (make-array 0 :element-type 'hash-table
				     :adjustable t :fill-pointer 0))
	 certificates)
    (handler-case
	(fast-io:with-fast-input (certs-stream buffer nil 7)
	  (loop
	    while (< (fast-io:buffer-position certs-stream) (length buffer))
	    with length-octets = (fast-io:make-octet-vector 3)
	    for index upfrom 0
	    for length = (progn
			   (fast-io:fast-read-sequence length-octets certs-stream)
			   (octets-to-integer length-octets))
	    for cert = (fast-io:make-octet-vector length)
	    do
	       (fast-io:fast-read-sequence cert certs-stream)
	       (vector-push-extend cert raw-certificates)))
      (end-of-file nil
	(error 'exception
	       :log "Invalid encoding of certificate message"
	       :alert :decode-error)))
    (when (> (length raw-certificates) *max-certificate-chain-length*)
      (error 'exception
	     :log "Peer sent a certificate chain of more than maximum allowed (20)"
	     :alert :decode-error))
    (setf certificates (make-array (length raw-certificates)
				   :element-type 'hash-table))
    (loop for index upfrom 0 below (length certificates)
	  for cert = (aref raw-certificates index)
	  do
	     (setf (aref certificates index)
		   (handler-case
		       (x509-decode cert)
		     (x509-decoding-error (err)
		       (error 'exception
			      :log (format nil "Error parsing certificate: ~A" (text err))
			      :alert :bad-certificate)))))
    (unless (validate session certificates)
      (error 'exception
	     :log "Certificate path validation failed"
	     :alert :bad-certificate))
    ;; Parse the primary certificate, the first one in the chain, retrieve the public key)
    (let* ((certificate (tbs-certificate (aref certificates 0)))
	   (extensions (extensions certificate))
	   (alt-names (subject-alternative-name extensions))
	   (dns-names (loop
			for name in alt-names
			when (eql (car name) :dns-name)
			  collect (cdr name)))
	   (ip-addresses (loop
			   for name in alt-names
			   when (eql (car name) :ip-address)
			     collect (cdr name)))
	   (subject-pki (subject-pki certificate))
	   (subject-pk-algorithm (getf subject-pki :algorithm-identifier))
	   (subject-pk (getf subject-pki :subject-public-key)))
      (with-slots (key-exchange-method
		   authentication-method remote-certificate-type
		   dh-params dh-Y pub-key
		   peer-ip-addresses peer-dns-name) session
	;; Verify the right kind of certificate was sent
	(setf remote-certificate-type (first subject-pk-algorithm))
	(case remote-certificate-type
	  (:rsa
	   (setf pub-key
		 (ironclad:make-public-key :rsa :n (getf subject-pk :modulus)
						:e (getf subject-pk :public-exponent))))
	  (:dsa
	   (setf pub-key
		 (ironclad:make-public-key :dsa
					     :p (getf subject-pk :dsa-p)
					     :q (getf subject-pk :dsa-q)
					     :g (getf subject-pk :dsa-g)
					     :y (getf subject-pk :dsa-public-key))))
	  (:dh
	   ;; TODO support for parameter l (prime-length)
	   (setf dh-params (generate-dh-params :p (getf subject-pk :dh-P)
					       :g (getf subject-pk :dh-G)))
	   (setf dh-Y (getf subject-pk :dh-Y))))
	;; Ensure the subject and subjectAltNames match
	(when peer-dns-name
	  (unless dns-names
	    (error 'exception
		   :log "Server does not identify its domain name in its certificate"
		   :alert :bad-certificate))
	  (unless (some (lambda (arg)
			  (dns-match-p arg peer-dns-name))
			dns-names)
	    (error 'exception
		   :log "DNS mismatch"
		   :alert :bad-certificate)))
	(when peer-ip-addresses
	  (unless ip-addresses
	    (error 'exception
		   :log "Server does not identify its IP in its certificate"
		   :alert :bad-certificate))
	  (loop for ip in ip-addresses
		unless (member ip peer-ip-addresses :test #'equalp)
		  do (error 'exception
			    :log "IP address mismatch"
			    :alert :bad-certificate)))))))

;; Define the encryption key size
;; 			  Key      IV   Block
;; Cipher        Type    Material  Size  Size
;; ------------  ------  --------  ----  -----
;; NULL          Stream      0       0    N/A
;; RC4_128       Stream     16       0    N/A
;; 3DES_EDE_CBC  Block      24       8      8
;; AES_128_CBC   Block      16      16     16
;; AES_256_CBC   Block      32      16     16
;; 
;; MAC       Algorithm    mac_length  mac_key_length
;; --------  -----------  ----------  --------------
;; NULL      N/A              0             0
;; MD5       HMAC-MD5        16            16
;; SHA       HMAC-SHA1       20            20
;; SHA256    HMAC-SHA256     32            32

(defmethod handle-handshake (buffer session (type (eql :server-hello)))
  (with-slots (server-random resumable session-id) session
    (with-specification-map ((version 2)
			     (random 32)
			     (session_id (0 32))
			     (cipher-suite 2)
			     (compression-method 1)
			     (extensions (0 65535)))
      (subseq buffer 4)
      (error 'exception
	     :log "Malformed ServerHello message"
	     :alert :decode-error)
      (setf server-random (subseq random 0))
      (when resumable
	(setf session-id (subseq session_id 0)))
      (parse-cipher-suite cipher-suite session)
      ;; TODO: Parse extensions and compression fields
      (values version compression-method extensions))))

(defgeneric get-record (session))

(defmethod get-record ((session session))
  (handler-case
      (with-slots
	    (io-stream input-stream role handshake-messages
	     version state
	     sequence-number-read session-read-state) session
	(let* ((stream (or io-stream input-stream))
	       (content-type (read-byte stream))
	       (record-version (get-sequence stream 2))
	       (length (stream-octets-to-integer stream 2))
	       (fragment (cond ((> length (expt 2 14))
				(error 'exception
				       :log (format nil "Record overflow. Length: ~A" length)
				       :alert :record-overflow))
			       (t
				(get-sequence stream length)))))
	  (if (eql :encrypted session-read-state)
	      (setf fragment
		    (ciphertext-to-compressed session content-type fragment)))
	  ;; Incf the sequence number
	  (incf sequence-number-read)
	  ;; If an alert is received while connecting, signal an error
	  (when (and (eql state :connecting)
		     (= content-type +alert+))
	    (error 'tls-error
		   :text (alert-record-to-text fragment)))
	  (values content-type fragment version)))
    (stream-error ()
      (error 'tls-stream-error))))

(defun get-change-cipher-spec (session)
  (multiple-value-bind (content-type content) (get-record session)
    (switch (content-type :test #'=)
	    (+alert+
	     (error 'tls-error :text (alert-record-to-text content)))
	    (+change-cipher-spec+
	     (with-slots (sequence-number-read session-read-state) session
	       (setf session-read-state :encrypted)
	       (setf sequence-number-read 0)))
	    (otherwise
	     (error 'exception
		    :log "Unexpected record type, expected ChangeCiperSpec"
		    :alert :unexpected-message)))))

(let ((fragment (fast-io:make-octet-vector 0)))
  (defun reassemble-handshake-message (session &optional handshake-fragment)
    "Handle defragmentation of handshake messages"
    (and handshake-fragment
	 (setf fragment handshake-fragment))
    (cond ((zerop (length fragment))
	   (multiple-value-bind (content-type content) (get-record session)
	     (or (= content-type +handshake+)
		 (error 'exception
			:log "Unexpected message. Expected handshake message"
			:alert :unexpected-message))
	     (let* ((content-length (- (length content) 4))
		    (message-length (octets-to-integer content :start 1 :end 4)))
	       (cond ((> message-length content-length)
		      (loop
			while (< (length content) message-length)
			do
			   (multiple-value-bind (content-type more-content version)
			       (get-record session)
			     (or (= content-type +handshake+)
				 (error 'exception
					:log "Unexpected message. Expected handshake message"
					:alert :unexpected-message))
			     (setf content (cat-vectors content more-content))))
		      (if (= (- (length content) 4) message-length)
			  content
			  (progn
			    (setf fragment
				  (subseq content
					  (+ 4 (octets-to-integer content :start 1 :end 4))))
			    (subseq content 0 (+ 4 (octets-to-integer content :start 1 :end 4))))))
		     ((< message-length content-length)
		      (setf fragment
			    (subseq content
				    (+ 4 (octets-to-integer content :start 1 :end 4))))
		      (subseq content 0 (+ 4 (octets-to-integer content :start 1 :end 4))))
		     ((= message-length content-length)
		      content)))))
	  (t
	   (let* ((content (copy-seq fragment))
		  (content-length (- (length content) 4))
		  (message-length (octets-to-integer content :start 1 :end 4)))
	     (setf fragment (adjust-array fragment 0))
	     (cond ((> message-length content-length)
		    (loop
		      while (< (length content) message-length)
		      do
			 (multiple-value-bind (content-type more-content version)
			     (get-record session)
			   (or (= content-type +handshake+)
			       (error 'exception
				      :log "Unexpected message. Expected handshake message"
				      :alert :unexpected-message))
			   (setf content (cat-vectors content more-content))))
		    (if (= (- (length content) 4) message-length)
			content
			(progn
			  (setf fragment
				(subseq content
					(+ 4 (octets-to-integer content :start 1 :end 4))))
			  (subseq content 0 (+ 4 (octets-to-integer content :start 1 :end 4))))))
		   ((< message-length content-length)
		    (setf fragment
			  (subseq content
				  (+ 4 (octets-to-integer content :start 1 :end 4))))
		    (subseq content 0 (+ 4 (octets-to-integer content :start 1 :end 4))))
		   ((= message-length content-length)
		    content)))))))

(defun get-handshake-message (session &optional handshake-fragment)
  (let ((content (reassemble-handshake-message session handshake-fragment)))
    (with-slots (role handshake-stage handshake-messages) session
      (cond ((vectorp handshake-stage)
	     (unless (find (aref content 0) handshake-stage)
	       (error 'exception
		      :log (format nil "~&Unexpected handshake message, expected ~S, received ~S~%" handshake-stage (aref content 0))
		      :alert :unexpected-message)))
	    (t
	     (unless (= (aref content 0) handshake-stage)
	       (unless (find (aref content 0) handshake-stage)
		 (error 'exception
			:log (format nil "~&Unexpected handshake message, expected ~S, received ~S~%" handshake-stage (aref content 0))
			:alert :unexpected-message)))))
      ;; Call handshake handler
      (handle-handshake
       content session
       (switch ((aref content 0) :test #'=)
	       (+hello-request+ :hello-request)
	       (+client-hello+ :client-hello)
	       (+server-hello+ :server-hello)
	       (+server-hello-done+ :server-hello-done)
	       (+certificate+ :certificate)
	       (+server-key-exchange+ :server-key-exchange)
	       (+certificate-request+ :certificate-request)
	       (+certificate-verify+ :certificate-verify)
	       (+client-key-exchange+ :client-key-exchange)
	       (+finished+ :finished)
	       (otherwise
		(error 'exception
		       :log "Unknown handshake message"
		       :alert :decode-error))))
      ;; Except for hello_request and finished messages, concatenate to handshake-messages
      (and (/= (aref content 0) +finished+)
	   (/= (aref content 0) +hello-request+)
	   (setf handshake-messages
		 (cat-vectors handshake-messages content))))))

(defun get-application-data (session eof-error-p eof-value)
  "Get application data, take care of renegotiation transparently"
  (with-slots (role state handshake-messages) session
    (tagbody
     try-again
       (if (eql state :closed)
	   (if eof-error-p (error 'end-of-file)
	       (return-from get-application-data eof-value))
	   (multiple-value-bind (content-type content) (get-record session)
	     (switch (content-type :test #'=)
		     (+handshake+
		      (cond ((and (= (aref content 0) +hello-request+)
				  (eql role :client))
			     (initiate-connection session)
			     (go try-again))
			    ((and (= (aref content 0) +client-hello+)
				  (eql role :server))
			     (setf content (get-handshake-message session content))
			     (initiate-connection session :skip-hello t)
			     (go try-again))
			    (t
			     (error 'exception
				    :log "Unexpected record, expected ApplicationData"
				    :alert :unexpected-message))))
		     (+alert+
		      (cond
			((= +close-notify+ (aref content 1))
			 (send-alert session :warning :close-notify)
			 (setf state :closed)
			 (if eof-error-p
			     (error 'end-of-file)
			     (return-from get-application-data eof-value)))
			(t
			 (if (= +fatal+ (aref content 0))
			     (error 'tls-error :text (alert-record-to-text content))
			     (warn (alert-record-to-text content))))))
		     (+application-data+
		      (return-from get-application-data content))
		     (otherwise
		      (error 'exception
			     :log "Unexpected record, expected ApplicationData"
			     :alert :unexpected-message))))))))

(defgeneric initiate-connection (session &key))

(defmethod initiate-connection ((session client-session) &key)
  "Attempt a handshake as a client"
  (with-slots
	(handshake-stage
	 state key-exchange-method priv-key
	 authentication-method certificate
	 certificate-requested handshake-messages)
      session
    (send-handshake session :client-hello)
    ;; Get the server hello
    (setf handshake-stage +server-hello+)
    (get-handshake-message session)
    
    ;; Get the server certificate if the key exchange method is not DH-anon
    (cond ((eql authentication-method :anon)
	   (setf handshake-stage +server-hello+))
	  (t
	   (setf handshake-stage +certificate+)
	   (unless (eql authentication-method :anon) (get-handshake-message session))))
    
    ;; Get the Server Key Exchange message if DHE_DSS DHE_RSA or DH_anon
    (when (or (and (eql key-exchange-method :dhe)
		   (find authentication-method '(:dsa :rsa)))
	      (and (eql key-exchange-method :dh)
		   (eql authentication-method :anon)))
      (setf handshake-stage +server-key-exchange+)
      (get-handshake-message session))
    ;; Get the server hello done or certificateRequest
    (setf handshake-stage (vector +server-hello-done+ +certificate-request+))
    (get-handshake-message session)
    ;; If it was a certificateRequest, get the serverHelloDone
    (when certificate-requested
      (get-handshake-message session))
    ;; If a session certificate was requested, send it
    (when certificate-requested
      (send-handshake session :client-certificate))
    ;; Send the clientKeyExchange
    (send-handshake session :client-key-exchange)
    ;; Send the certificateVerify
    (and certificate-requested
	 certificate
	 (unless (eql (first
		       (getf (subject-pki (tbs-certificate (x509-decode (first certificate))))
			     :algorithm-identifier))
		      :dh)
	   (send-handshake session :certificate-verify)))
    ;; Send the changeCipherText
    (send-change-cipher-spec session)
    ;; We have everything we need now to generate keying material
    (gen-key-material session)
    ;; Send the session finished
    (send-handshake session :finished)
    ;; Get the remote ChangeCipherSpec
    (get-change-cipher-spec session)
    ;; Get the finished message
    (setf handshake-stage +finished+)
    (get-handshake-message session)
    ;; Clean up
    (setf handshake-messages (adjust-array handshake-messages 0))
    
    (format *debug-stream* "~&TLS Session successfully started~%")))

(defmethod initiate-connection ((session server-session) &key skip-hello)
  "Attempt a handshake as a server"
  (with-slots
	(handshake-stage
	 priv-key certificate authenticate-client-p
	 key-exchange-method authentication-method
	 remote-certificate-type handshake-messages)
      session
    ;; Get client hello
    (or skip-hello
	(progn (setf handshake-stage +client-hello+)
	       (get-handshake-message session)))
    ;; Send the server hello
    (send-handshake session :server-hello)
    ;; Send the server certificate
    (send-handshake session :certificate)
    ;; Send the Server Key Echange for DHE_DSS, DHE_RSA, and DH_anon
    (when (or (and (eql key-exchange-method :dhe)
		   (find authentication-method '(:dsa :rsa)))
	      (and (eql key-exchange-method :dh)
		   (eql authentication-method :anon)))
      (send-handshake session :server-key-exchange))
    (when authenticate-client-p
      (send-handshake session :certificate-request))
    
    ;; Send the serverHelloDone
    (send-handshake session :server-hello-done)

    ;; Get the client certificate, if it was requested
    (when authenticate-client-p
      (setf handshake-stage +certificate+)
      (get-handshake-message session))
    
    ;; Get the client key exchange
    (setf handshake-stage +client-key-exchange+)
    (get-handshake-message session)

    ;; Get the certificateVerify
    (when authenticate-client-p
      (unless (and remote-certificate-type
		   (eql key-exchange-method :dh))
	(setf handshake-stage +certificate-verify+)
	(get-handshake-message session)))
    
    ;; Get the remote ChangeCipherSpec
    (get-change-cipher-spec session)
    ;; We have everything we need now to generate keying material
    (gen-key-material session)
    ;; Get the finished message
    (setf handshake-stage +finished+)
    (get-handshake-message session)
    ;; Send the ChangeCipherSpec
    (send-change-cipher-spec session)
    ;; Send the server finished
    (send-handshake session :finished)
    ;; Clean up
    (setf handshake-messages (adjust-array handshake-messages 0))
    
    (format *debug-stream* "~&TLS Session successfully started~%")))

(defun get-private-key (path)
  (let ((private-key-info (load-priv-key (get-contents path))))
    (case (getf private-key-info :private-key-algorithm)
      (:rsa
       (ironclad:make-private-key :rsa :d (getf private-key-info :private-exponent)
				       :n (getf private-key-info :modulus)))
      (:dsa
       (ironclad:make-private-key :dsa
				  :p (getf private-key-info :dsa-p)
				  :q (getf private-key-info :dsa-q)
				  :g (getf private-key-info :dsa-g)
				  :x (getf private-key-info :dsa-x)))
      (:dh
       (getf private-key-info :dh-X)))))

(defun dhparams-from-key-file (path)
  (let ((pki (load-priv-key (get-contents path))))
    (generate-dh-params :p (getf pki :dh-P)
			:g (getf pki :dh-G))))

(defun symbol-to-suite-list (sym)
  (case sym
    (:rsa-ke +rsa-key-exchange-suites+)
    (:dh +dh-key-exchange-suites+)
    (:dhe +dhe-key-exchange-suites+)
    (:rsa-auth +rsa-authentication-suites+)
    (:dsa +dss-authentication-suites+)
    (:anon +anon-authentication-suites+)
    (:rc4 +rc4-encryption-suites+)
    (:3des +3des-encryption-suites+)
    (:aes128 +aes-128-ciphers+)
    (:aes256 +aes-256-ciphers+)
    (:cbc +cbc-mode-ciphers+)
    (:md5 +md5-ciphers+)
    (:sha1 +sha1-ciphers+)
    (:sha256 +sha256-ciphers+)
    (otherwise (error "~&Unknown cipher suites symbol ~S~%" sym))))

(defun create-cipher-vector (include exclude &optional authentication-method)
  (when authentication-method
    (when (eql authentication-method :rsa)
      (setf authentication-method :rsa-auth))
    (setf exclude (append exclude
			  (case authentication-method
			    (:dsa
			     (list :rsa-auth #|:ecdsa|#))
			    (:rsa-auth
			     (list :dsa #|:ecdsa|#))
			    (:ecdsa
			     (list :rsa-auth :dsa))))))
  (let* ((add-suites
	   (loop for sym in include appending (symbol-to-suite-list sym)))
	 (remove-suites
	   (loop for sym in exclude appending (symbol-to-suite-list sym)))
	 (suites
	   (delete-duplicates
	    (remove-if
	     (lambda (arg) (member arg remove-suites :test #'equal))
	     (union *supported-cipher-suites* add-suites :test #'equal))
	    :test #'equal))
	 (vec (fast-io:make-octet-vector (* (length suites) 2)))
	 (len (length vec)))
    (loop
      for suite in suites
      for a from 0 below len by 2
      for b from 1 below len by 2
      do
	 (setf (aref vec a) (aref suite 0))
	 (setf (aref vec b) (aref suite 1)))
    vec))

(defun get-dh-params (path)
  (let ((contents (get-contents path)))
    (when (typep contents 'simple-string)
      (setf contents (first (parse-pem contents)))
      (unless (equalp (car contents) "DH PARAMETERS")
	(error
	 "~&Expected ~S but instead found ~S in ~S~%"
	 "DH PARAMETERS" (car contents) path))
      (setf contents (cdr contents)))
    (setf contents (multiple-value-list (parse-der contents)))
    (unless (and (asn-type-matches-p :sequence contents)
		 (<= 2 (length (second contents)) 3)
		 (every (lambda (arg) (asn-type-matches-p :integer arg))
			(second contents)))
      (error "Could not load DH parameters from ~S" path))
    (destructuring-bind (p g &optional plen) (second contents)
      (declare (ignorable plen))
      (generate-dh-params :p (second p) :g (second g)))))

(defun get-ca-certificates (path)
  (unless (probe-file path)
    (error "File/Directory ~S does not exist" path))
  (flet ((parse-cert (file)
	   (let ((contents (get-contents file)))
	     (cond ((typep contents 'octet-vector)
		    (list (x509-decode contents)))
		   (t
		    (loop
		      with x509 = nil
		      for pem in (parse-pem contents)
		      when (equalp (car pem) "CERTIFICATE")
			do
			   (setf x509
				 (handler-case (x509-decode (cdr pem))
				   (x509-decoding-error (e)
				     (warn "Skipped a certificate from ~S because of an x509 decoding error:~%~A." file (slot-value e 'text)))))
		      when x509 collect x509))))))
    (cond ((plusp (length (file-namestring (truename path))))
	   (parse-cert path))
	  (t
	   (loop
	     for file in (find-certificates path)
	     nconcing (parse-cert file))))))

(defun create-session (role
		       &key certificate private-key ca-certificates
			 io-stream input-stream output-stream
			 include-ciphers exclude-ciphers
			 peer-dns-name peer-ip-addresses)
  (assert (or io-stream
	      (and input-stream output-stream)))
  (assert (and (listp include-ciphers)
	       (listp include-ciphers)))
  (ecase role
    (:client
     (or peer-dns-name
	 peer-ip-addresses
	 (error
	  "You must provide either a DNSname of a list of IP addresses of the server."))
     (make-instance 'client-session
		    :role :client
		    :private-key (if private-key
				     (get-private-key private-key))
		    :certificate (if certificate
				     (loop
				       for cert in (parse-pem (get-contents certificate))
				       collecting (cdr cert)))
		    :ca-certificates (if ca-certificates
					 (get-ca-certificates ca-certificates))
		    :io-stream io-stream
		    :input-stream input-stream
		    :output-stream output-stream
		    :ciphers (create-cipher-vector include-ciphers exclude-ciphers)
		    :peer-dns-name peer-dns-name
		    :peer-ip-addresses peer-ip-addresses))
    (:server
     (make-instance 'server-session
		    :io-stream io-stream
		    :input-stream input-stream
		    :output-stream output-stream))))

(defun create-listener-session
    (&key private-key certificate ca-certificates
       include-ciphers exclude-ciphers dh-params
       authenticate-client-p require-authentication-p)
  (let* ((certificates (and certificate
			    (loop
			      for cert in (parse-pem (get-contents certificate))
			      collecting (cdr cert)))))
    (make-instance 'shared-session-slots
		   :private-key (and private-key
				     (get-private-key private-key))
		   :certificate (and certificate
				     certificates)
		   :ca-certificates (and ca-certificates
					 (get-ca-certificates ca-certificates))
		   :ciphers (create-cipher-vector
			     include-ciphers exclude-ciphers
			     (when certificates
			       (first
				(getf (subject-pki
				       (tbs-certificate (x509-decode (first certificates))))
				      :algorithm-identifier))))
		   :dh-params (unless (or (member :dh exclude-ciphers)
					  (member :dhe exclude-ciphers))
				(or (and dh-params
					 (get-dh-params dh-params))
				    (and private-key
					 (dhparams-from-key-file private-key))
				    (generate-dh-params)))
		   :authenticate-client-p (or require-authentication-p
					      authenticate-client-p)
		   :require-authentication-p require-authentication-p)))

(defun request-tunnel (&key certificate private-key ca-certificates
			 io-stream input-stream output-stream
			 include-ciphers exclude-ciphers
			 peer-dns-name peer-ip-addresses)
  "As a client, request a TLS connection from a server"
  (let ((session (create-session
		  :client
		  :certificate certificate
		  :private-key private-key
		  :io-stream io-stream
		  :input-stream input-stream
		  :output-stream output-stream
		  :peer-dns-name peer-dns-name
		  :peer-ip-addresses peer-ip-addresses
		  :exclude-ciphers exclude-ciphers
		  :ca-certificates ca-certificates
		  :include-ciphers include-ciphers)))
    (handler-case (initiate-connection session)
      (exception (err)
	(format t "~&Handshake error: ~A~%" (log-info err))
	(send-alert session :fatal (alert err))
	(return-from request-tunnel)))
    ;; A TLS tunnel has now been established, set the data callback function
    (with-slots (state) session
      (values
       ;; Return a reader function
       (lambda (&key (eof-error-p nil) (eof-value nil))
	 (handler-case
	     (get-application-data session eof-error-p eof-value)
	   (exception (err)
	     (format t "~&TLS error : ~A~%" (log-info err))
	     (send-alert session :fatal (alert err))
	     (error 'tls-error :text (log-info err)))))
       ;; Return the write function, expects an octet vector as the sole argument.
       (lambda (octet-vector)
	 (if (eql state :closed)
	     (error 'tunnel-closed)
	     (send session +application-data+ octet-vector)))
       ;; Close function
       (lambda ()
	 (send-alert session :warning :close-notify)
	 (setf state :closed))))))

(let ((listener-shared-resources))
  (defun initialize-listener (&key certificate private-key ca-certificates
				include-ciphers exclude-ciphers force-reinitialize
				authenticate-client-p require-authentication-p
				dh-params)
    "Initialize a TLS server session with the given arguments"
    (cond ((and listener-shared-resources force-reinitialize)
	   (error "The listener is already initialized."))
	  (t
	   (setf listener-shared-resources
		 (create-listener-session
		  :certificate certificate
		  :private-key private-key
		  :dh-params dh-params
		  :ca-certificates ca-certificates
		  :authenticate-client-p authenticate-client-p
		  :require-authentication-p require-authentication-p
		  :exclude-ciphers exclude-ciphers))))
    t))

(defun accept-tunnel (&key io-stream input-stream output-stream)
  "As a server, accept a new connection from a client"
  (let ((new-client-session (create-session :server
					    :io-stream io-stream
					    :input-stream input-stream
					    :output-stream output-stream)))
    (handler-case (initiate-connection new-client-session)
      (exception (err)
	(format *debug-stream* "~&Handshake error: ~A~%" (log-info err))
	(send-alert new-client-session :fatal (alert err))
	(error 'tls-error :text (log-info err))
	(return-from accept-tunnel)))
    (with-slots (state) new-client-session
      (values
       ;; Return a reader function
       (lambda (&key (eof-error-p nil) (eof-value nil))
	 (handler-case
	     (get-application-data new-client-session eof-error-p eof-value)
	   (exception (err)
	     (format *debug-stream* "~&TLS error : ~A~%" (log-info err))
	     (send-alert new-client-session :fatal (alert err))
	     (error 'tls-error :text (log-info err)))))
       ;; Return the write function, expects an octet vector as the sole argument.
       (lambda (octet-vector)
	 (if (eql state :closed)
	     (error 'tunnel-closed)
	     (send new-client-session +application-data+ octet-vector)))
       ;; Close function
       (lambda ()
	 (send-alert new-client-session :warning :close-notify)
	 (setf state :closed))))))
