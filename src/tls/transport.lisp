;; Some parts of tls require an implementation to perform
;; http, ldap, or other kind of network-based communication.
;; Defined here are classes and methods to be specialized to
;; provide such service
(in-package :cl-tls)

(defclass address ()
  ((host :initarg :host
	 :accessor host)
   (port :initarg :port
	 :accessor port)))

(defgeneric request-stream-to-address (address))

(defmethod request-stream-to-address ((addr address))
  (error "Oops, looks like you forgot to specialize cl-tls:get-stream-to-address"))
