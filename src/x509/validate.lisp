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

(defun check-certificate-status (session subject issuer)
  "Check certificate status via OCSP.
   If the OCSP request is successful and the status os good, return true.
   Return false in every other case"
  (with-slots ((subject-tbs-certificate tbs-certificate)) subject
    (with-slots ((subject-extensions extensions)) subject-tbs-certificate
      (let* ((ocsp-status
	       (and 
		(getf (authority-information-access subject-extensions) :ocsp)
		;; Certificate has an ocsp url
		(handler-case
		    (check-ocsp subject issuer)
		  (ocsp-error (err)
		    (format
		     t
		     "Error encountered while checking the certificate status. Details: ~A"
		     (log-info err))
		    :error)))))
	(or (null ocsp-status)
	    (eql ocsp-status :good))))))

(defun validate (session chain)
  "Certificate Path validation, including status checking"
  (loop
    with last-index = (1- (length chain))
    for index upfrom 0 below (length chain)
    do
       ;; Check validity
       (unless (time-valid-p (aref chain index))
	 (return-from validate nil))
       (cond ((= last-index index)
	      (with-slots (ca-certificates) session
		(let* ((subject (aref chain index))
		       (subject-tbs (tbs-certificate subject))
		       (issuers (loop with issuers = nil
				      for ca in ca-certificates
				      do 
					 (cond ((equal (subject (tbs-certificate ca))
						       (issuer subject-tbs))
						(push ca issuers))
					       ((equal (subject (tbs-certificate ca))
						       (subject subject-tbs))
						(return :trusted)))
				      finally (return issuers)))
		       (issuer
			 (and (listp issuers)
			      (loop
				with authority-key-identifier = (authority-key-identifier
								 (extensions subject-tbs))
				for ca in issuers
				when (equalp
				      (getf
				       authority-key-identifier :key-identifier)
				      (subject-key-identifier (extensions (tbs-certificate ca))))
				  return ca))))
		  (or (eql issuers :trusted)
		      (unless (and issuer
				   (verify-signature subject issuer))
			(return-from validate nil))))))
		(t
		 (let ((subject (aref chain index))
		    (issuer (aref chain (1+ index))))
		(unless (check-certificate-status session subject issuer)
		  (return-from validate nil))
		(unless (equal (issuer (tbs-certificate subject))
			       (subject (tbs-certificate issuer)))
		  (return-from validate nil))
	        (unless (verify-signature subject issuer)
		  (return-from validate nil))))))
  t)
