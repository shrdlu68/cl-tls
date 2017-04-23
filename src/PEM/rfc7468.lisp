;; This is an implementation of rfc7468, to facilitate reading PEM-encoded
;; Private Key Info and Certificates

;; Textual encoding begins with a line comprising "-----BEGIN ", a
;; label, and "-----", and ends with a line comprising "-----END ", a
;; label, and "-----".  Between these lines, or "encapsulation
;;    boundaries", are base64-encoded data according to Section 4 of
;; [RFC4648].  (PEM [RFC1421] referred to this data as the "encapsulated
;; text portion".)  Data before the encapsulation boundaries are
;; permitted, and parsers MUST NOT malfunction when processing such
;; data.  Furthermore, parsers SHOULD ignore whitespace and other non-
;; base64 characters and MUST handle different newline conventions.
(in-package :cl-tls)

(defun decapsulate (txt prefix suffix &key (start 0) (end (length txt)))
  "Read string encapsulated between a prefix and suffix"
  (when-let* ((prefix-start (search prefix txt :start2 start :end2 end))
	      (prefix-end (+ prefix-start (length prefix)))
	      (suffix-start (search suffix txt :start2 prefix-end :end2 end))
	      (suffix-end (+ suffix-start (length suffix))))
	     (values
	      (subseq txt prefix-end suffix-start)
	      suffix-end)))

(defun parse-pem (text)
  (loop
     with offset = 0
     for header = (decapsulate text "-----BEGIN " "-----" :start offset)
     for pem-header = (concatenate 'string "-----BEGIN " header "-----")
     for pem-footer = (concatenate 'string "-----END " header "-----")
     for (pem next-offset) = (multiple-value-list
			      (decapsulate text pem-header pem-footer :start offset))
     while pem
     do
       (setf offset next-offset)
     collect
       (cons header 
	     (cl-base64:base64-string-to-usb8-array pem))))
