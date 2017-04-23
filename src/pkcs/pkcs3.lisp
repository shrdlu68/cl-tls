;; PKCS#3

(in-package :cl-tls)

(defclass dh-params ()
  ((p :initarg :p :reader prime-modulus :type integer)
   (g :initarg :g :reader generator :type integer)))

(defun strong-random-range (a b)
  "Generate a random integer between a and b, inclusive"
  (do* ((r 0 (+ r (ironclad:strong-random (- b r)))))
       ((<= a r b) r)))

(defun generate-dh-params (&key (L 2048) p g)
  (let* ((p (or p (ironclad:generate-prime L)))
	 (g (or g (strong-random-range 1 (1- p)))))
    (make-instance 'dh-params :p p :g g)))

(defun make-dh-key-pair (dh-params &optional static)
  "Generate a Private/Public key pair"
  (with-slots (p g) dh-params
    (let* ((x (or static (strong-random-range 1 (1- p))))
	   (y (ironclad:expt-mod g x p)))
      (values x y))))

(defun compute-shared-secret (dh-params secret-exp dh-public-value)
  "Generates the final secret, given the dh-params and the dh-public-value of the other party"
  (with-slots (p) dh-params
    (ironclad:expt-mod dh-public-value secret-exp p)))
