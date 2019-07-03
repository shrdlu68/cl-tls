;; Miscallenous helper functions
(in-package :cl-tls)

(declaim (optimize (debug 3)))

(setf ironclad:*prng* (crypto:make-prng :fortuna :seed :urandom))

(deftype octet ()
  '(unsigned-byte 8))

(deftype octet-vector ()
  '(simple-array octet *))

(defun make-octet-vector (&key length initial-contents)
  (if initial-contents
      (make-array (length initial-contents) :element-type 'octet :initial-contents initial-contents)
      (make-array length :element-type 'octet)))

(defun bytes-in-int(int)
  "Return the least number of octets needed to represent an integer"
  (ceiling (integer-length int) 8))

(defun octets-to-integer (ov &key (start 0) (end (length ov)))
  (do ((i (1- end) (1- i))
       (n 0 (+ n 8))
       (int 0 (logior int (ash (aref ov i) n))))
      ((< i start) int)))

(defun integer-to-octets(int &optional (length (bytes-in-int int)))
  "Convert an integer into a network-byte-ordered vector of octets,
   padded with zeros if the number of octets in int is less than length."
  (let ((vec (fast-io:make-octet-vector length)))
    (loop
      for pos from 0 by 8
      for index from (1- (length vec)) downto 0
      do
	 (setf (aref vec index)
	       (ldb (byte 8 pos) int)))
    vec))

(defun timing-independent-compare (vec1 vec2)
  "Compare octet vectors in a time-independent manner"
  (declare (optimize (speed 0)))
  (and (= (length vec1) (length vec2))
       (let ((equality 0))
	 (declare (type octet equality))
	 (loop
	   for x across vec1
	   for y across vec2
	   do (setf equality (logior equality (logxor x y))))
	 (zerop equality))))

(defun cat-vectors (&rest vectors)
  (fast-io:with-fast-output
      (out)
    (loop
      for vec in vectors
      do
	 (fast-io:fast-write-sequence vec out))))

(defun get-random-octets(n &optional (buffer (fast-io:make-octet-vector n)))
  "Return a series of n octets from a cryptographically secure source"
  (with-open-file (dev-urandom "/dev/urandom" :direction :input :element-type 'octet)
    (loop
      for n from 0 below (length buffer)
      do
	 (setf (aref buffer n) (read-byte dev-urandom))))
  buffer)

(defun gmt-unix-time()
  "Return a number representing the seconds that have elapsed since January 1, 1970"
  (- (get-universal-time) (encode-universal-time 0 0 0 1 1 1970 0)))

;; <floor>..<ceiling>
;; Any variable length vector is preceded by length octets that occupy the maximum
;; number of octets needed to represent the ceiling
;; Generates code that does all the bounds checks necessary to ensure the message is
;; well-formed. The extension field in server_hello and client_hello is the exception
;; to this rule. Presence of this field is detected by checking whether there are bytes
;; present after the compression methods
(defmacro with-specification-map (map vec error-clause &body b)
  (with-gensyms (vec-length fields error-lambda)
    (let ((syms (loop for li in map collecting (first li))))
      (when (equal (first (last syms)) 'extensions)
	(setf syms (append (butlast syms) (list '&optional 'extensions))))
      `(let ((,vec-length (length ,vec))
	     ,fields
	     (,error-lambda (lambda () ,error-clause)))
	 (loop
	   with offset = 0
	   with length-octets = 0
	   with field-length = 0
	   for li in ',map do
	     (cond ((listp (second li))
		    (setf length-octets (bytes-in-int (second (second li))))
		    (cond
		      ((<= (+ offset length-octets) ,vec-length)
		       (setf field-length
			     (octets-to-integer (subseq ,vec offset
							(+ offset length-octets))))
		       (unless (>= field-length (first (second li)))
			 (funcall ,error-lambda))
		       (incf offset length-octets)
		       (if (<= (+ offset field-length) ,vec-length)
			   (setf ,fields
				 (append ,fields
					 (list (if (zerop field-length)
						   nil
						   (subseq ,vec offset
							   (+ offset field-length))))))
			   (funcall ,error-lambda))
		       (incf offset field-length))
		      (t
		       (unless (equal (first li) 'extensions)
			 (funcall ,error-lambda)))))
		   (t
		    (if (<= (+ offset (second li)) ,vec-length)
			(setf ,fields
			      (append ,fields (list (subseq ,vec offset
							    (+ offset (second li))))))
			(funcall ,error-lambda))
		    (incf offset (second li)))))
	 (destructuring-bind ,syms ,fields ,@b)))))

(defun get-contents (path)
  "Get the contents of the file, either as text if it is text content or as an octet vector otherwise"
  (unless (probe-file path)
    (error "File ~A does not exist" path))
  (let* ((ov (alexandria:read-file-into-byte-vector path)))
    (handler-case (babel:octets-to-string ov :encoding :utf-8)
      (babel-encodings:character-decoding-error nil ov))))

(defun asn-type-matches-p (type info)
  (eql (first info) type))

(defun dump-to-file (ov file-spec)
  (with-open-file (fd file-spec :direction :output
				:if-does-not-exist :create :if-exists :supersede
				:element-type 'octet)
    (loop for uint8 across ov do
      (write-byte uint8 fd))))

(defun get-sequence (stream length)
  (let ((seq (fast-io:make-octet-vector length)))
    (read-sequence seq stream)
    seq))

(defun stream-octets-to-integer (stream length)
  (let ((ov (get-sequence stream length)))
    (octets-to-integer ov)))

(defun find-certificates (dir)
  (loop for type in '("crt" "pem" "der")
	nconcing (directory (make-pathname
			     :name :wild
			     :type type
			     :directory dir))))

(defun dns-match-p (pattern dns-name)
  "Simple pattern matching for dns names.
   Only accepts one wildcard subdomain name."
  (cond ((find #\* pattern :test #'char=)
	 (and (>= (length pattern) 6)	; *.a.bc
	      (= (count #\* pattern :test #'char=) 1)
	      (= (position #\* pattern :test #'char=) 0)
	      (>= (count #\. pattern) 2)
	      (not (search ".." pattern))
	      (search "*." pattern)
	      (char/= #\* (char pattern (1- (length pattern))))
	      (string-equal (subseq pattern 1)
			    (subseq dns-name (position #\. dns-name)))))
	(t
	 (equalp pattern dns-name))))

(defun split-string (str target)
  (loop with len = (length str)
	for start = 0 then (search str target :start2 (1+ start) :test #'char=)
	while (and start
		   (< (+ start len) (length target)))
	collecting (subseq target (if (zerop start)
				      0
				      (+ start len))
			   (search str target :start2 (1+ start) :test #'char=))))
