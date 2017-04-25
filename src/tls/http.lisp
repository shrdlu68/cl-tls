;; Specialized http client for OSCP requests, CRL, and others.
;; Rigorous input validation, especially for length fields

(in-package :cl-tls)

(define-condition http-error (error)
  ((log :initarg :log
	:accessor log-info)))
   
(defclass uri ()
  ((scheme :initarg :scheme
	   :accessor scheme)
   (host :initarg :host
	 :accessor host)
   (port :initarg :port
	 :accessor port)
   (path :initarg :path
	 :accessor path)))

(defparameter *crlf* (format nil "~C~C" #\return #\newline))

(defparameter *max-content-length* (* 10 1024 1024))

(defun parse-uri (uri)
  "Parse URI into its components as specified in rfc3986"
  (when-let*
   ((uri-len (length uri))
    (first-colon-pos (position #\: uri :test #'char=))
    (scheme (subseq uri 0 first-colon-pos))
    (authority-start (and (array-in-bounds-p uri (+ 3 first-colon-pos))
			  (+ 3 first-colon-pos)))
    (authority-end (or (loop for index from authority-start below uri-len
			     when (member (char uri index)
					  '(#\/ #\? #\#) :test #'char=)
			       return index)
		       uri-len))
    (authority (subseq uri authority-start authority-end))
    (host (cond ((and (position #\[ authority :test #'char=)
		      (position #\] authority :test #'char=))
		 ;; iPv6 literal
		 (subseq authority
			 (1+ (position #\[ authority :test #'char=))
			 (position #\] authority :test #'char=)))
		(t
		 ;; iPv4 literal or domain-name
		 (or (and (position #\: authority :test #'char=)
			  (subseq authority 0
				  (position #\: authority :test #'char=)))
		     authority))))
    (port (let ((host-port-separator (if (and (position #\[ authority :test #'char=)
					      (position #\] authority :test #'char=))
					 (position
					  #\: authority
					  :test #'char=
					  :start (position #\] authority :test #'char=))
					 (position #\: authority :test #'char=))))
	    (cond (host-port-separator
		   (and (array-in-bounds-p authority (1+ host-port-separator))
			(subseq authority (1+ host-port-separator))))
		  (t
		   80))))
    (path (if (= authority-end uri-len)
	      "/"
	      (subseq uri authority-end))))
   (make-instance 'uri
		  :scheme scheme
		  :host host
		  :port port
		  :path path)))

(defun read-header (stream)
  "Read one header from stream"
  (with-output-to-string (out)
    (loop for uint8 = (read-byte stream)
	  for len upfrom 1
	  until (= uint8 10)
	  do
	     (when (> len 1024)
	       (error 'http-error :log "Received a header larger than max allowed"))
	     (when (> uint8 127)
	       (error 'http-error :log "Illegal character in headers"))
	     (unless (= uint8 13)
	       (write-char (code-char uint8) out)))))

(defun trim-space (str)
  (string-trim '(#\space #\tab) str))

(defun split-header (header)
  "Split header into its key and value components"
  (let ((colon-pos (or (position #\: header)
		       (error 'http-error :log "Malformed header"))))
    (when (= colon-pos (1- (length header)))
      (error 'http-error :log "Malformed header"))
    (list (trim-space (subseq header 0 colon-pos))
	  (trim-space (subseq header (1+ colon-pos))))))

(defun parse-headers-from-stream (stream)
  "Reapetedly read headers from stream"
  (loop for n upfrom 1
	for header = (read-header stream)
	while (plusp (length header))
	when (> n 20) do
	  (error 'http-error :log "Too many headers (max 20)")
	collecting header))

(defun header-value (header-key headers)
  (loop for header in headers
	when (string-equal (first header) header-key)
	  return (second header)))

(defun read-chunk (stream)
  "Read a single chunk, or nil upon receiving 0-length header"
  (let* ((chunk-size-line (read-header stream))
	 (chunk-size-text (if (position #\; chunk-size-line)
			      (subseq chunk-size-line 0 (position #\; chunk-size-line))
			      chunk-size-line))
	 (chunk-size (parse-integer chunk-size-text :radix 16 :junk-allowed t)))
    (and (zerop chunk-size)
	 (return-from read-chunk nil))
    (or chunk-size
	(error 'http-error :log "Malformed chunk size"))
    (or (< chunk-size *max-content-length*)
	(error 'http-error :log "Chunk size larger than max content length."))
    (let ((chunk (fast-io:make-octet-vector chunk-size)))
      (read-sequence chunk stream)
      ;; Read CR
      (or (= (read-byte stream) 13)
	  (error 'htt-error :log "Malformed chunk"))
      ;; Read LF
      (or (= (read-byte stream) 10)
	  (error 'htt-error :log "Malformed chunk"))
      chunk)))
	   
(defun read-chunked-response (stream)
  (fast-io:with-fast-output (out)
    (loop for chunk = (read-chunk stream)
	  for response-length = (length chunk) then (+ response-length (length chunk))
	  while chunk do
	    (and (> response-length *max-content-length*)
		 (error 'http-error :log "Content size past max limit"))
	    (fast-io:fast-write-sequence chunk out))))

(defun http-get (url &optional body)
  "Retrieve response body of http transaction"
  (prog ((redirections 0))
   redirect
     (setf url (parse-uri url))
     (or url
	 (error 'http-error
		:log "URL is not well-formed"))
     (let* ((headers (concatenate
		      'string
		      (format nil "GET ~A HTTP/1.1" (path url)) *crlf*
		      (format nil "Host: ~A" (host url)) *crlf*
		      "Connection: close" *crlf*
		      (when body
			(concatenate 'string
				     "Content-Type: application/octet-stream" *crlf*
				     (format nil "Content-Length: ~A" (length body))
				     *crlf*)
			"")
		      *crlf*))
	    (address (make-instance 'address
				    :host (host url)
				    :port (port url)))
	    (stream (request-stream-to-address address)))
       (write-sequence (babel:string-to-octets headers) stream)
       (when body
	 (write-sequence body stream))
       (finish-output stream)
       ;; Read response headers
       (let* ((response-headers (parse-headers-from-stream stream))
	      (status-line (split-string " " (first response-headers)))
	      (version (first status-line))
	      (status-code (second status-line))
	      (status-phrase (apply #'concatenate 'string (cddr status-line))))
	 (setf response-headers (loop for header in (cdr response-headers)
				      collecting (split-header header)))
	 (unless version status-code status-phrase
		 (error 'http-error :log "Malformed status lines"))
	 (unless (every #'digit-char-p status-code)
	   (error 'http-error :log "Malformed status code"))
	 (setf status-code (parse-integer status-code))
	 (or (string-equal version "HTTP/1.1")
	     (string-equal version "HTTP/1.0")
	     (error 'http-error
		    :log (format nil "Unrecognized http version ~S" version)))
	 (cond
	   ((= status-code 200)
	    (let ((transfer-encoding
		    (header-value "Transfer-Encoding" response-headers)))
	      (cond (transfer-encoding
		     (if (string-equal transfer-encoding "chunked")
			 (return (read-chunked-response stream))
			 (error 'http-error
				:log (format nil
					     "Unknown transfer-encoding ~S"
					     transfer-encoding))))
		    (t
		     (let ((content-length
			     (header-value "Content-Length" response-headers))
			   response-body)
		       (unless (every #'digit-char-p content-length)
			 (error 'http-error :log "Malformed content-length"))
		       (setf content-length (parse-integer content-length))
		       (when (> content-length *max-content-length*)
			 (error 'http-error :log "Content-Legth past limit"))
		       (setf response-body (fast-io:make-octet-vector content-length))
		       (read-sequence response-body stream)
		       (return response-body))))))
	   ((or (= status-code 301)
		(= status-code 302)
		(= status-code 303)
		(= status-code 307))
	    ;; Redirect
	    (setf url (header-value "Location" response-headers))
	    (or url (error 'http-error
			   :log "Received a redirect byt no Location header"))
	    (incf redirections)
	    (when (> redirections 5)
	      (error 'http-error :log "Too many redirections"))
	    (go redirect))
	   (t
	    ;; Some other code we're not expecting
	    (error 'http-error
		   :log (format nil "Unexpected response. Code: ~S Phrase: ~S"
				status-code status-phrase))))))))
