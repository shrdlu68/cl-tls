;; X9.42/RFC 2631
(in-package :cl-tls)
(setf ironclad:*prng* (crypto:make-prng :fortuna :seed :urandom))

(defclass dh-params ()
  ((p :initarg :p :reader prime-modulus :type integer)
   (g :initarg :g :reader generator :type integer)
   (q :initarg :q :reader factor :type integer)
   (m :initarg :m :reader privkey-length :type integer)))

(defun generate-dh-params (&optional (m (* 160 3)) (L 2048))
  (prog* ((mx (ceiling m 160))
          (Lx (ceiling L 160))
          (N (ceiling L 1024))
          seed seed-int q counter R p j h g)
   four
     (setf seed (ironclad:random-data (ceiling m 8)))
     (setf seed-int (octets-to-integer seed))
     (setf q (do* ((i 0 (1+ i))
                   (q 0 (+ q (* (logxor (octets-to-integer
					 (ironclad:digest-sequence :sha1
                                                                   (integer-to-octets
                                                                    (+ seed-int i))))
					(octets-to-integer
					 (ironclad:digest-sequence :sha1
                                                                   (integer-to-octets
                                                                    (+ seed-int i mx)))))
				(expt 2 (* 160 i))))))
                  ((= i mx) q)))
     (setf q (mod (logior q (expt 2 (1- m)) 1) (expt 2 m)))
     (format t "---") (finish-output)
     (unless (ironclad:prime-p q)
       (go four))
     (setf counter 0)
   eight
     (setf R (+ seed-int (* 2 mx) (* counter Lx)))
     (setf p (do ((i 0 (1+ i))
                  (V 0 (+ V (* (octets-to-integer
				(ironclad:digest-sequence :sha1 (ironclad:integer-to-octets (+ i R))))
                               (expt 2 (* 160 i))))))
		 ((= i Lx) V)))
     (setf p (mod (logior p (expt 2 (1- L))) (expt 2 L)))
     (setf p (- p (1+ (mod p (* q 2)))))
     (format t "...") (finish-output)
     (when (> p (expt 2 (1- L)))
       (if (ironclad:prime-p p)
           (go gen-g)))
     (incf counter)
     (if (< counter (* 4096 N))
	 (go eight))
   gen-g
     (setf j (ceiling (1- p) q))
   step-2
     (setf h (do ((h 0 (ironclad:strong-random (1- p))))
		 ((< 1 h (1- p)) h)))
     (setf g (ironclad:expt-mod h j p))
     (if (= g 1) (go step-2))
     (assert (= p (1+ (* q j))))
     (format t "~&P: ~S~%" p)
     (format t "~&qj + 1: ~S~%" (1+ (* q j)))
     (return (make-instance 'dh-params :p p :g g :q q :m m))))

(defun strong-random-range (a b)
  "Generate a random integer between a and b, inclusive"
  (do* ((r 0 (+ r (ironclad:strong-random (- b r)))))
       ((<= a r b) r)))

(defun make-dh-key-pair (dh-params)
  "Generate a Private/Public key pair"
  (with-slots (p g q m) dh-params
    (let* ((min (expt 2 (1- m)))
	   (max (- q 2))
	   (x (octets-to-integer
	       (ironclad:random-data (strong-random-range (ceiling (integer-length min) 8)
							  (floor (integer-length max) 8)))))
	   (y (ironclad:expt-mod g x p)))
      (values x y))))

(defun compute-shared-secret (dh-params secret-exp dh-public-value)
  "Generates the final secret, given the dh-params and the dh-public-value of the other party"
  (with-slots (p) dh-params
    (ironclad:expt-mod dh-public-value secret-exp p)))
