;; Certificate validation and revocation-checking
(in-package :cl-tls)

(defun get-issuer-octets (cert)
  "Get the raw der-encoded contents of the issuer field in the certificate"
  (let* ((certificate (first (asn-sequence-to-indices cert)))
	 (tbs-certificate (asn-sequence-to-indices cert (second certificate)))
	 (issuer (if (= (first (first tbs-certificate)) 0)
		     (fourth tbs-certificate)
		     (third tbs-certificate)))
	 (contents-start (second issuer))
	 (contents-end (third issuer))
	 (length (- contents-start contents-end)))
    (if (<= length 127)
	(subseq cert (- contents-start 2) contents-end)
	(subseq cert (- contents-start 2 (bytes-in-int length)) contents-end))))

(defun get-pubkey-octets (cert)
  "Get the raw der-encoded contents of the public key field in the certificate"
  (let* ((certificate (first (asn-sequence-to-indices cert)))
	 (tbs-certificate (asn-sequence-to-indices cert (second certificate)))
	 (subject-pki (if (= (first (first tbs-certificate)) 0)
			  (seventh tbs-certificate)
			  (sixth tbs-certificate)))
	 (subject-pki-indices (asn-sequence-to-indices cert (second subject-pki)))
	 (subject-public-key (second subject-pki-indices)))
    (subseq cert (1+ (second subject-public-key)) (third subject-public-key))))

(defun check-certificate-status (session subject raw-subject issuer raw-issuer)
  "Check certificate status via OCSP.
   If the OCSP request is successful and the status os good, return true.
   Return false in every other case"
  (let* ((ocsp-status
	   (and 
	    (getf (gethash :authority-information-access subject) :ocsp)
	    ;; Certificate has an ocsp url
	    (handler-case
		(check-ocsp subject raw-subject issuer raw-issuer)
	      (ocsp-error (err)
		(format
		 t
		 "An error occured while checking the status of the certificate. Details: ~A"
		 (log-info err))
		:error)))))
    (or (null ocsp-status)
	(eql ocsp-status :good))))

(defun validate (session decoded-chain raw-chain)
  "Certificate Path validation. decode-chain is the chain of certificates, decoded.
   chain is the chain of certificates, der-encoded."
  (loop
    with last-index = (1- (length decoded-chain))
    for index upfrom 0 below (length decoded-chain)
    do
       ;; Check validity
       (unless (time-valid-p (aref decoded-chain index))
	 (return-from validate nil))
       (cond ((= last-index index)
	      (with-slots (ca-certificates) session
		(let* ((subject (aref decoded-chain index))
		       (issuers (loop
				  for ca in ca-certificates
				  when (equal (gethash :subject ca)
					      (gethash :issuer subject))
				    collect ca))
		       (issuer
			 (loop
			   with authority-key-identifier = (gethash
							    :authority-key-identifier
							    subject)
			   for ca in issuers
			   when (equalp
				 (getf
				  authority-key-identifier :key-identifier)
				 (gethash :subject-key-identifier ca))
			     return ca)))
		  (unless (and issuer
			       (verify-signature subject issuer))
		    (return-from validate nil)))))
	     (t
	      (let ((subject (aref decoded-chain index))
		    (raw-subject (aref raw-chain index))
		    (issuer (aref decoded-chain (1+ index)))
		    (raw-issuer (aref raw-chain (1+ index))))
		(unless (check-certificate-status session
						  subject raw-subject
						  issuer raw-issuer)
		  (return-from validate nil))
		(unless (equal (gethash :issuer subject)
			       (gethash :subject issuer))
		  (return-from validate nil))
	        (unless (verify-signature subject issuer)
		  (return-from validate nil))))))
  t)
