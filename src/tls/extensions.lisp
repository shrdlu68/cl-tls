;; https://tools.ietf.org/html/rfc5246#section-7.4.1.4
;; https://tools.ietf.org/html/rfc6066
(in-package :cl-tls)

(defgeneric parse-extension (session extension-data type))

(defmethod parse-extension (session extension-data (type (eql :server-name)))
  (with-slots (extensions-data) session
    (fast-io:with-fast-input (server-name-list extension-data)
      (handler-case
	  (loop
	     for sn-length = (fast-io:readu16-be server-name-list)
	     for sn = (fast-io:make-octet-vector sn-length)
	     while (< (fast-io:buffer-position server-name-list) (length extensions-data))
	     do
	       (fast-io:fast-read-sequence sn server-name-list)
	       (case (aref sn 0)
		 (0 (push
		     (handler-case
			 (babel:octets-to-string sn :encoding :ascii)
		       (babel:character-decoding-error nil
			 (error 'exception
				:log "SNI hostname is not ASCII"
				:alert :decode-error)))
		     (gethash :host-name extensions-data)))
		 (otherwise
		  (error 'exception
			 :log "Unknown SNI name_type"
			 :alert :illegal-parameter))))
	(end-of-file nil
	  (error 'exception
		 :log "Invalid encoding of SNI extension"
		 :alert :decode-error))))))

(defmethod parse-extension (session extension-data (type (eql :max-fragment-length)))
  (cond ((plusp (length extension-data))
	 (with-slots (extensions-data) session
	   (setf (gethash :max-fragment-length extensions-data)
		 (case (aref extension-data 0)
		   (1 (expt 2 9))
		   (2 (expt 2 10))
		   (3 (expt 2 11))
		   (4 (expt 2 12))
		   (otherwise
		    (error 'exception
			   :log "Illegal/Unsupported MaxFragmentLength"
			   :alert :illegal-parameter))))))
	(t
	 (error 'exception
		:log "Bad MaxFragmentLength extension-data"
		:alert :decode-error))))

(defmethod parse-extension (session extension-data (type (eql :client-certificate-url)))
  (with-slots (extensions-data) session
    (setf (gethash :client-certificate-url extensions-data) t)))

(defmethod parse-extension (session extension-data (type (eql :signature-algorithm)))
  (flet ((fail ()
	   (error 'exception
		  :log "Bad SignatureAlgorithm extension-data"
		  :alert :decode-error)))
    (let ((len (- (length extension-data) 2)))
      (unless (evenp len) (fail))
      (with-slots (extensions-data) session
	(setf (gethash :supported-signature-algorithms extensions-data)
	      (loop
		 for hash from 2 by 2 below len
		 for sig from 3 by 2 below len
		 collecting
		   (list
		    (case (aref extension-data hash)
		      (1 :md5) (2 :sha1) (3 :sha224)
		      (4 :sha256) (5 :sha384) (6 :sha512)
		      (otherwise (fail)))
		    (case (aref extension-data sig)
		      (1 :rsa) (2 :dsa) (3 :ecdsa)
		      (otherwise (fail))))))))))

(defmethod parse-extension (session extension-data (type (eql :trusted-ca-keys)))
  ;; TODO
  )

(defmethod parse-extension (session extension-data (type (eql :truncated-hmac)))
  ;; TODO
  )

(defmethod parse-extension (session extension-data (type (eql :status-request)))
  ;; TODO
  )

(defun pack-extension (extension-type extension-data)
  (let* ((ext-len (length extension-data))
	 (ext (fast-io:make-octet-vector (+ 2 2 ext-len))))
    (replace ext
	     (integer-to-octets (case extension-type
				  (:signature-algorithms 13) (:server-name 0)
				  (:max-fragment-length 1) (:trusted-ca-keys 3)
				  (:truncated-hmac 4) (:status-request 5)
				  (otherwise (error "Unsupported extension type")))
				2))
    (replace ext (integer-to-octets ext-len 2) :start1 2)
    (replace ext extension-data :start1 4)
    ext))

(defun create-sni (fqdn)
  (let* ((fqdn-octets (babel:string-to-octets fqdn :encoding :ascii))
	 (hostname-len (length fqdn-octets))
	 (server-name-list
	   (fast-io:make-octet-vector (+ 2 1 2 hostname-len))))
    (replace server-name-list
	     (integer-to-octets (+ 1 2 hostname-len) 2))
    (setf (aref server-name-list 2) 0)
    (replace server-name-list (integer-to-octets hostname-len 2)
	     :start1 3)
    (replace server-name-list fqdn-octets :start1 5)
    (pack-extension :server-name server-name-list)))
