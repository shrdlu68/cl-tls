;; These are the standard extensions in RFC5280,
;; see https://tools.ietf.org/html/rfc5280#section-4.1.2.9
(in-package :cl-tls)

(defgeneric process-extension (x509 critical-p value type))

;; GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

;; GeneralName ::= CHOICE {
;; otherName                       [0]     OtherName,
;; rfc822Name                      [1]     IA5String,
;; dNSName                         [2]     IA5String,
;; x400Address                     [3]     ORAddress,
;; directoryName                   [4]     Name,
;; ediPartyName                    [5]     EDIPartyName,
;; uniformResourceIdentifier       [6]     IA5String,
;; iPAddress                       [7]     OCTET STRING,
;; registeredID                    [8]     OBJECT IDENTIFIER }

(defun parse-general-name (general-name)
  (case (first general-name)
    (0
     ;; 
     )
    (1
     (cons :rfc822-name
	   (handler-case
	       (babel:octets-to-string (second general-name) :encoding :ascii)
	     (babel:character-decoding-error nil
	       (error 'x509-decoding-error
		      :text "Invalid rfc822Name")))))
    (2
     ;; dNSName, an IA5String
     (let ((dns-name (handler-case
			 (babel:octets-to-string (second general-name) :encoding :ascii)
		       (babel:character-decoding-error nil
			 (error 'x509-decoding-error
				:text "Invalid dNSName")))))
       (unless (and (plusp (length dns-name))
		    (not (equal dns-name " ")))
	 (error 'x509-decoding-error
		:text "Invalid dNSName"))
       (cons :dns-name dns-name)))
    (3
     ;; 
     )
    (4
     ;; directoryName
     (let ((name (multiple-value-list (parse-der (second general-name)))))
       (unless (eql (first name) :sequence)
	 (error 'x509-decoding-error :text "Invalid  directoryName"))
       (cons :directory-name (parse-directory-name (second name)))))
    (5
     ;; 
     )
    (6
     ;; uniformResourceIdentifier
     (let ((uri (handler-case
			 (babel:octets-to-string (second general-name) :encoding :ascii)
		       (babel:character-decoding-error nil
			 (error 'x509-decoding-error
				:text "Invalid URL")))))
       (cons :uri uri)))
    (7
     ;; iPAddress
     (or (= (length (second general-name)) 4)
	 (= (length (second general-name)) 16)
	 (error 'x509-decoding-error :text "Invalid iPAddress"))
     (cons :ip-address (second general-name)))
    (8
     (cons :registered-id (decode-oid (second general-name))))
    (otherwise
     (error 'x509-decoding-error
	    :text "Illegal/Unknown GeneralName"))))

(defun parse-general-names (general-names)
  "Return a bag of generalNames"
  (loop
     for general-name in general-names
     collecting (parse-general-name general-name)))

(defmethod process-extension (x509 critical-p value (type (eql :subject-alternative-name)))
  (handler-case
      (multiple-value-bind (asn-type general-names) (parse-der value)
	(unless (eql :sequence asn-type)
	  (error 'x509-decoding-error
		 :text "Invalid SubjectAlternativeName GeneralNames"))
	(setf (gethash :subject-alternative-name x509)
	      (parse-general-names general-names)))
  (asn.1-decoding-error (e)
			(error 'x509-decoding-error
			       :text (format nil "An ASN.1 decoding error was encountered while processing the SubjectAlternativeName extension. Details: ~A~%" (slot-value e 'text))))))

(defmethod process-extension (x509 critical-p value (type (eql :issuer-alternative-name)))
  (handler-case
      (multiple-value-bind (asn-type general-names) (parse-der value)
	(unless (eql :sequence asn-type)
	  (error 'x509-decoding-error :text "Invalid IssuerAlternativeName GeneralNames"))
	(setf (gethash :issuer-alternative-name x509) (parse-general-names general-names)))
    (asn.1-decoding-error (e)
      (error 'x509-decoding-error
	     :text (format nil "An ASN.1 decoding error was encountered while processing the IssuerAlternativeName extension. Details: ~A~%" (slot-value e 'text))))))

(defmethod process-extension (x509 critical-p value (type (eql :authority-key-identifier)))
  ;; AuthorityKeyIdentifier ::= SEQUENCE {
  ;; 	keyIdentifier             [0] KeyIdentifier           OPTIONAL,
  ;; 	authorityCertIssuer       [1] GeneralNames            OPTIONAL,
  ;; 	authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
  (handler-case
      (flet ((fail ()
	       (error 'x509-decoding-error
		      :text "Invalid authorityKeyIdentifier extension data")))
	(setf value (multiple-value-list (parse-der value)))
	(unless (eql (first value) :sequence) (fail))
	(setf value (second value))
	(unless (<= 0 (length value) 3) (fail))
	(let (key-id)
	  (loop
	     for id in value
	     do
	       (case (first id)
		 (0;; keyIdentifier
		  (setf (getf key-id :key-identifier) (second id)))
		 (1;; GeneralNames
		  (let ((general-names (asn-sequence-to-list (second id))))
		    (setf (getf key-id :authority-cert-issuer)
			  (parse-general-names general-names))))
		 (2;; CertificateSerialNumber
		  (setf (getf key-id :authority-cert-serial-number)
			(octets-to-integer (second id))))
		 (otherwise (fail))))
	  (setf (gethash :authority-key-identifier x509) key-id)))
    (asn.1-decoding-error (e)
      (error 'x509-decoding-error
	     :text (format nil "An ASN.1 decoding error was encountered while processing the AuthorityKeyIdentifier extension. Details: ~A~%" (slot-value e 'text))))))

(defmethod process-extension (x509 critical-p value (type (eql :subject-key-identifier)))
  ;; KeyIdentifier ::= OCTET STRING
  (handler-bind ((asn.1-decoding-error
		  #'(lambda (e)
		      (error 'x509-decoding-error
			     :text (format nil "An ASN.1 decoding error was encountered while processing the SubjectKeyIdentifier extension. Details: ~A~%" (slot-value e 'text))))))
    (setf value (multiple-value-list (parse-der value)))
    (unless (eql (first value) :octet-string)
      (error 'x509-decoding-error :text "Invalid SubjectKeyIdentifier extension data"))
    (setf (gethash :subject-key-identifier x509) (second value))))

(defmethod process-extension (x509 critical-p value (type (eql :key-usage)))
  (handler-bind ((asn.1-decoding-error
		  #'(lambda (e)
		      (error 'x509-decoding-error
			     :text (format nil "An ASN.1 decoding error was encountered while processing the KeyUsage extension. Details: ~A~%" (slot-value e 'text))))))
    (setf value (multiple-value-list (parse-der value)))
    (unless (eql (first value) :bit-string)
      (error 'x509-decoding-error :text "Invalid keyUsage extension data"))
    (let ((bit-string (aref (second value) 1))
	  usage)
      (setf
       (getf usage :digital-signature) (= (ldb (byte 1 0) bit-string) 1)
       (getf usage :non-repudiation) (= (ldb (byte 1 1) bit-string) 1)
       (getf usage :key-encipherment) (= (ldb (byte 1 2) bit-string) 1)
       (getf usage :data-encipherment) (= (ldb (byte 1 3) bit-string) 1)
       (getf usage :key-agreement) (= (ldb (byte 1 4) bit-string) 1)
       (getf usage :key-cert-sign) (= (ldb (byte 1 5) bit-string) 1)
       (getf usage :crl-sign) (= (ldb (byte 1 6) bit-string) 1)
       (getf usage :encipherment-only) (= (ldb (byte 1 7) bit-string) 1)
       (getf usage :decipherment-only) (= (ldb (byte 1 8) bit-string) 1))
      (setf (gethash :key-usage x509) usage))))
  
(defun parse-qualifier (policy-qualifier-id qualifier)
  ;; Qualifier ::= CHOICE {
  ;; cPSuri           CPSuri,
  ;; userNotice       UserNotice }
  (flet ((fail ()
	   (error 'x509-decoding-error :text "Invalid certificatePolicies extension data")))
    (let (result)
      (switch (policy-qualifier-id :test #'equal)
	      ('(1 3 6 1 5 5 7 2 1);; cps
		;; CPSuri ::= IA5String
		(unless (asn-type-matches-p :ia5-string qualifier) (fail))
		(setf (getf result :cpsuri) (second qualifier)))
	      ('(1 3 6 1 5 5 7 2 2);; unotice
		;;
		(unless (asn-type-matches-p :sequence qualifier) (fail))
		(setf qualifier (second qualifier))
		(unless (<= 0 (length qualifier) 2) (fail))
		(let (unotice)
		  (loop
		     for notice in qualifier
		     do
		     ;; UserNotice ::= SEQUENCE {
		     ;; noticeRef        NoticeReference OPTIONAL,
		     ;; explicitText     DisplayText OPTIONAL }
		     ;; NoticeReference ::= SEQUENCE {
		     ;; organization     DisplayText,
		     ;; noticeNumbers    SEQUENCE OF INTEGER }
		       (when (asn-type-matches-p :sequence notice);; noticeRef
			 (let (notice-ref)
			   (setf notice (second notice))
			   (unless (= (length notice) 2) (fail))
			   (destructuring-bind (organization notice-numbers) notice
			     (unless
				 (find
				  (first organization)
				  '(:ia5-string :visible-string :bmp-string :utf8-string)
				  :test #'eql)
			       (fail))
			     (setf (getf notice-ref :organization) (second organization))
			     (unless (asn-type-matches-p :sequence notice-numbers)
			       (fail))
			     (setf notice-numbers (second notice-numbers))
			     (setf (getf notice-ref :notice-numbers)
				   (loop
				      for number in notice-numbers
				      do
					(unless (asn-type-matches-p :integer number) (fail))
				      collect
					(second number))))
			   (setf (getf unotice :notice-reference) notice-ref)))
		       (when (find
			      (first notice)
			      '(:ia5-string :visible-string :bmp-string :utf8-string)
			      :test #'eql)
			 (setf (getf unotice :explicit-text) (second notice))))
		  (setf (getf result :user-notice) unotice))))
      result)))

(defmethod process-extension (x509 critical-p value (type (eql :certificate-policies)))
  (handler-case
      (flet ((fail ()
	       (error 'x509-decoding-error
		      :text "Invalid certificatePolicies extension data")))
	(setf value (multiple-value-list (parse-der value)))
	(unless (eql (first value) :sequence) (fail))
	(setf value (second value))
	(let (policies)
	  (loop
	     for policy-information in value
	     do
	       (let (policy)
		 (unless (eql (first policy-information) :sequence) (fail))
		 (setf policy-information (second policy-information))
		 (unless (<= 1 (length policy-information) 2) (fail))
		 (destructuring-bind (policy-identifier &optional policy-qualifiers)
		     policy-information
		   (unless (eql (first policy-identifier) :oid) (fail))
		   (setf policy-identifier (second policy-identifier))
		   (when policy-qualifiers
		     (unless (eql (first policy-qualifiers) :sequence) (fail))
		     (setf policy-qualifiers (second policy-qualifiers))
		     (loop
			for policy-qualifier-info in policy-qualifiers
			do
			  (unless (asn-type-matches-p :sequence policy-qualifier-info)
			    (fail))
			  (setf policy-qualifier-info (second policy-qualifier-info))
			  (unless (= (length policy-qualifier-info) 2) (fail))
			  (destructuring-bind (policy-qualifier-id qualifier)
			      policy-qualifier-info
			    (unless (asn-type-matches-p :oid policy-qualifier-id) (fail))
			    (setf policy-qualifier-id (second policy-qualifier-id))
			    (setf policy
				  (append policy
					  (parse-qualifier policy-qualifier-id
							   qualifier))))))
		   (setf policies (acons policy-identifier policy policies)))))
	  (setf (gethash :certificate-policies x509) policies)))
    (asn.1-decoding-error (e)
      (error 'x509-decoding-error
	     :text (format nil "An ASN.1 decoding error was encountered while processing the CertificatePolicies extension. Details: ~A~%" (slot-value e 'text))))))

(defmethod process-extension (x509 critical-p value (type (eql :policy-mappings)))
  (handler-case
      (flet ((fail ()
	       (error 'x509-decoding-error :text "Invalid policyMappings extension data")))
	(multiple-value-bind (asn-type policy-mappings) (parse-der value)
	  (unless (eql asn-type :sequence) (fail))
	  (setf (gethash :policy-mappings x509)
		(loop
		   for policy-mapping in policy-mappings
		   do
		     (unless (and (asn-type-matches-p :sequence policy-mapping)
				  (= (length (second policy-mapping)) 2))
		       (fail))
		   collect
		     (destructuring-bind (issuer subject) (second policy-mapping)
		       (unless (and (eql (first issuer) :oid )
				    (eql (first subject) :oid)) (fail))
		       (list :issuer-domain-policy (second issuer)
			     :subject-domain-policy (second subject)))))))
    (asn.1-decoding-error (e)
      (error 'x509-decoding-error
	     :text (format nil "An ASN.1 decoding error was encountered while processing the PolicyMappings extension. Details: ~A~%" (slot-value e 'text))))))
		 

(defmethod process-extension (x509 critical-p value (type (eql :basic-constraints)))
  (handler-case
      (flet ((fail ()
	       (error 'x509-decoding-error :text "Invalid basicConstraints extension data")))
	(setf value (multiple-value-list (parse-der value)))
	(unless (eql (first value) :sequence) (fail))
	(setf value (second value))
	(unless (<= 0 (length value) 2) (fail))
	(destructuring-bind (&optional ca path-len-constraint) value
	  (unless (and (or (not ca)
			   (eql (first ca) :boolean))
		       (or (not path-len-constraint)
			   (eql (first path-len-constraint) :integer)))
	    (fail))
	  (let (basic-constraints)
	    (if ca
		(setf (getf basic-constraints :ca) (second ca))
		(setf (getf basic-constraints :ca) nil)) ;default
	    (when path-len-constraint
	      (setf
	       (getf basic-constraints :path-len-constraint)
	       (second path-len-constraint)))
	    (setf (gethash :basic-constraints x509) basic-constraints))))
    (asn.1-decoding-error (e)
      (error 'x509-decoding-error
	     :text (format nil "An ASN.1 decoding error was encountered while processing the BasicConstarints extension. Details: ~A~%" (slot-value e 'text))))))

(defmethod process-extension (x509 critical-p value (type (eql :name-constraints)))
  
  )

(defmethod process-extension (x509 critical-p value (type (eql :policy-constraints)))

  )

(defmethod process-extension (x509 critical-p value (type (eql :extended-key-usage)))
  (handler-case
      (flet ((fail ()
	       (error 'x509-decoding-error
		      :text "Error parsing ExtendedKeyUsage extension data")))
	(multiple-value-bind (type contents) (parse-der value)
	  (unless (eql type :sequence) (fail))
	  (setf (gethash :extended-key-usage x509)
		(loop
		   for key-purpose-id in contents
		   do
		     (unless (asn-type-matches-p :oid key-purpose-id) (fail))
		   collect
		     (switch ((second key-purpose-id) :test #'equal)
			     ('(1 3 6 1 5 5 7 3 1) :tls-web-server-authentication)
			     ('(1 3 6 1 5 5 7 3 2) :tls-web-client-authentication)
			     ('(1 3 6 1 5 5 7 3 3) :code-signing)
			     ('(1 3 6 1 5 5 7 3 4) :email-protection)
			     ('(1 3 6 1 5 5 7 3 5) :ipsec-end-system)
			     ('(1 3 6 1 5 5 7 3 6) :ipsec-tunnel)
			     ('(1 3 6 1 5 5 7 3 7) :ipsec-user)
			     ('(1 3 6 1 5 5 7 3 8) :time-stamping)
			     ('(1 3 6 1 5 5 7 3 9) :oscp-signing)
			     (otherwise (second key-purpose-id)))))))
    (asn.1-decoding-error (e)
      (error 'x509-decoding-error
	     :text (format nil "An ASN.1 decoding error was encountered while processing the ExtendedKeyUsage extension. Details: ~A~%" (slot-value e 'text))))))

(defmethod process-extension (x509 critical-p value (type (eql :crl-distribution-points)))
  (handler-case
      (flet ((fail ()
	       (error 'x509-decoding-error
		      :text "Error parsing CRLDistributionPoints extension data")))
	(multiple-value-bind (type crl-distribution-points) (parse-der value)
	  (unless (eql type :sequence) (fail))
	  (setf (gethash :crl-distribution-points x509)
		(loop
		   for distribution-point in crl-distribution-points
		   doing (unless (asn-type-matches-p :sequence distribution-point) (fail))
		   collecting
		     (loop
			for field in (second distribution-point) collecting
			  (case (first field)
			    (0;; distributionPoint
			     (multiple-value-bind (asn-type asn-contents) (parse-der (second field))
			       (case asn-type
				 (0;; fullName
				  (list :full-name
					(parse-general-names (asn-sequence-to-list asn-contents))))
				 (1;; nameRelativeToCRLIssuer
				  ;; 
				  ))))
			    (1;; reasons
			     ;; 
			     )
			    (2;; cRLIssuer
			     ;; 
			     )))))))
    (asn.1-decoding-error (e)
      (error 'x509-decoding-error
	     :text (format nil "An ASN.1 decoding error was encountered while processing the CRLDistributionPoints extension. Details: ~A~%" (slot-value e 'text))))))

(defmethod process-extension (x509 critical-p value (type (eql :inhibit-any-policy)))

  )

(defmethod process-extension (x509 critical-p value (type (eql :freshest-crl)))

  )

(defun parse-access-description (value)
  (flet ((fail ()
	   (error 'x509-decoding-error
		  :text "Error parsing AccessDescription")))
    (setf value (multiple-value-list (parse-der value)))
    (unless (eql (first value) :sequence) (fail))
    (setf value (second value))
    (let (info-access)
      (loop
	 for access-description in value
	 do
	   (unless (eql (first access-description) :sequence) (fail))
	   (setf access-description (second access-description))
	   (unless (= (length access-description) 2) (fail))
	   (destructuring-bind (access-method access-location) access-description
	     (unless (eql (first access-method) :oid) (fail))
	     (setf access-method (second access-method))
	     (cond
	       ((equal access-method '(1 3 6 1 5 5 7 48 2));; id-ad-caIssuers
		(setf (getf info-access :ca-issuers)
		      (parse-general-name access-location)))
	       ((equal access-method '(1 3 6 1 5 5 7 48 1));; id-ad-ocsp
		(setf (getf info-access :oscp)
		      (parse-general-name access-location))))))
      info-access)))

(defmethod process-extension (x509 critical-p value (type (eql :authority-information-access)))
  (handler-case
      (setf (gethash :authority-information-access x509) (parse-access-description value))
    (asn.1-decoding-error (e)
      (error 'x509-decoding-error
	     :text (format nil "An ASN.1 decoding error was encountered while processing the AuthorityInformationAccess extension. Details: ~A~%" (slot-value e 'text))))))

(defmethod process-extension (x509 critical-p value (type (eql :subject-information-access)))
  (handler-case
      (setf (gethash :subject-information-access x509) (parse-access-description value))
    (asn.1-decoding-error (e)
      (error 'x509-decoding-error
	     :text (format nil "An ASN.1 decoding error was encountered while processing the SubjectInformationAccess extension. Details: ~A~%" (slot-value e 'text))))))
