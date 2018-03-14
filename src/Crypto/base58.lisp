;; base58.lisp -- BTC-style base58 value encoding
;;
;; DM/Emotiq 02/18
;; ----------------------------------------------------------------
#|
The MIT License

Copyright (c) 2018 Emotiq AG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
|#

(in-package :base58)
;; ---------------------------------------------------------

;; This package describes interchangeable representations of vectors
;; of (unsigned-byte 8) values.
;;
;;            Class Hierarchy
;;            ---------------
;;
;;                 UB8V
;;                   |
;;      +-----+------+--------+-------+
;;      |     |      |        |       |
;;     LEV   BEV   BASE58   BASE64   HEX
;;
;; Class UB8V serves as an abstract superclass for all of these
;; parallel sub-classes. Any object of one of the subclasses can be
;; instantly converted into another parallel representation.
;;
;; Additionlly we make provision for conversion from bignum integers
;; to/from these vector representations.
;;
;; Finally, the Class UB8V-REPR is a mixin for future classes to use,
;; to indicate that they have the ability to produce a UB8V
;; representation, e.g., public keys, secret keys, compressed points
;; of Elliptic Curves, etc. This representation may be requested from
;; them with the UB8V-REPR method call.
;;
;; Type UB8 represents '(UNSIGNED-BYTE 8). Type UB8-VECTOR is defined
;; to represent any vector of actual UB8 values. Endian interpretation
;; is in the eye of the beholder.
;;
;; Each of the subclasses also has methods defined with the same name
;; as their class name, to perform conversions to their specific form
;; of representation. For example:
;;
;;    (base58 (lev #(1 2 3 4)))
;;  ==>
;;    #<BASE58 1111156wxj2 >
;;
;; These conversion operators may be applied to objects of any of the
;; parallel subclasses, as well as to INTEGER, LIST, and VECTOR. The
;; latter two must contain only elements of type UB8.
;;
;; The operators can also be applied to any class that inherits from
;; the mixin class UB8V-REPR and which implements a method by that
;; same name to return an instance of one of these parallel
;; subclasses. (c.f., PBC.LISP)

;; ----------------------------------------------------------
;; from https://bitcointalk.org/index.php?topic=1026.0

<<<<<<< HEAD
(um:defconstant+ +alphabet+
=======
(defconstant +alphabet-58+
>>>>>>> implicity type conversions to various vector representations - escape from "Type-less Hell"
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
(defconstant +len-58+
  (length +alphabet-58+)) ;; should be 58

(defvar +inv-alphabet-58+
  (let ((arr (make-array 256
                         :element-type '(unsigned-byte 8)
                         :initial-element 0)))
    (loop for c across +alphabet-58+
          for ix from 1
          do
          (setf (aref arr (char-code c)) ix))
    arr))

;; ----------------------------------------------------------

(defconstant +alphabet-64+
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defvar +inv-alphabet-64+
  (let ((arr (make-array 256
                         :element-type '(unsigned-byte 8)
                         :initial-element 0)))
    (loop for c across +alphabet-64+
          for ix from 1
          do
          (setf (aref arr (char-code c)) ix))
    arr))

;; ----------------------------------------------------------
;; Declare Types UB8 and UB8-VECTOR

(deftype ub8 ()
  '(unsigned-byte 8))

(deftype ub8-vector (&optional nel)
  `(array ub8 (,nel)))

;; ---------------------------------------------------------
;; Declare a useful mixin class to allow future classes to show a UB8V
;; representation

(defclass ub8v-repr ()
  ())

(defgeneric ub8v-repr (x)
  (:method ((x ub8v-repr))
   (error "Subclass responsibility")))

;; ---------------------------------------------------------
;; UB8V - the top abstract class of objects which represent
;; UB8-VECTORs. Declare a single slot to hold the data. Object of
;; these classes are intended to be immuatable.  All subclasses share
;; this same slot.

(defclass ub8v ()
  ((val :reader  ub8v-vec
        :initarg :vec)))

(defmethod print-object ((obj ub8v) out-stream)
  (format out-stream "#<~A ~A >"
          (class-name (class-of obj))
          (ub8v-vec obj)))

;; ----------------------------------------------------------
;; Base58 encodes UB8 vectors and integers into character strings of
;; the restricted alphabet. Encoding has a 6-character prefix that
;; represents the total number of bytes in the vector, up to 2^32
;; elements.

(defclass base58 (ub8v)
  ((val  :reader   base58-str
         :initarg  :str)
   ))

(defgeneric base58 (x))

;; ----------------------------------------------------------
;; Base64 encodes UB8 vectors and integers into character strings of
;; the restricted alphabet. Encoding has a 6-character prefix that
;; represents the total number of bytes in the vector, up to 2^32
;; elements.

(defclass base64 (ub8v)
  ((val  :reader   base64-str
         :initarg  :str)
   ))

(defgeneric base64 (x))

;; -----------------------------------------------------------
;; Hex-string representation, 1 char per 4-bit nibble

(defclass hex (ub8v)
  ((val  :reader hex-str
         :initarg :str)))

(defgeneric hex (x))

;; -----------------------------------------------------------
;; LEV-UB8 are little-endian vectors of UB8 elements

(defclass lev (ub8v)
  ((val  :reader   lev-vec
         :initarg  :vec)
   ))

(defgeneric lev (x))

;; -----------------------------------------------------------
;; BEV-UB8 are big-endian vectors of UB8 elements

(defclass bev (ub8v)
  ((val  :reader   bev-vec
         :initarg  :vec)
   ))

(defgeneric bev (x))

;; ---------------------------------------------------------
;; Encode to Base58 big-endian string

(defun sub-encode-58 (val nc s)
  (let ((cs nil))
    (um:nlet-tail iter ((v  val)
                        (ix 0))
      (when (or (plusp v)
                (and nc
                     (< ix nc)))
        (multiple-value-bind (vf vr) (floor v +len-58+)
          (push (char +alphabet-58+ vr) cs)
          (iter vf (1+ ix)))))
    (princ (coerce cs 'string) s)
    ))

(defun convert-vec-to-int (vec)
  (let ((val 0))
    (loop for v across vec
          for pos from 0 by 8
          do
          (setf val (dpb v (byte 8 pos) val)))
    val))

;; ---------------------------------------------------

(defmethod base58 ((x lev))
  ;; encode vector in blocks of 512 bytes = 4096 bits = 700 chars of
  ;; Base58 encoding. Output has first 6 chars to encode 4-byte length
  ;; prefix.
  (let* ((v   (lev-vec x))
         (nb  (length v)))
    (make-instance 'base58
                   :str (with-output-to-string (s)
                          (sub-encode-58 nb 6 s)
                          (um:nlet-tail iter ((start 0))
                            (unless (>= start nb)
                              (let* ((end   (min nb (+ start 512)))
                                     (chunk (subseq v start end)))
                                (sub-encode-58 (convert-vec-to-int chunk)
                                               (when (< end nb)
                                                 700)
                                               s)
                                (iter end))))
                          ))))

(defmethod base58 ((x base58))
  x)

(defmethod base58 (x)
  (base58 (lev x)))

;; -------------------------------------------------------------

(defmethod base64 ((x bev))
  (let* ((v   (bev-vec x))
         (nb  (length v))
         (ns  (* 4 (ceiling nb 3)))
         (str (make-string ns)))
    (um:nlet-tail iter ((start  0)
                        (vstart 0)
                        (val    0)
                        (ct     0))
      (labels
          ((enc (pos)
             (setf (char str (+ start pos))
                   (aref +alphabet-64+ (ldb (byte 6 (* 6 (- 3 pos))) val)))
             ))
        (when (>= ct 3)
          (enc 0)
          (enc 1)
          (enc 2)
          (enc 3)
          (setf val 0
                ct  0
                start (+ start 4)))
        (if (< vstart nb)
            (iter start (1+ vstart)
                  (dpb (aref v vstart) (byte 8 (* (- 2 ct) 8)) val)
                  (1+ ct))
          (progn
            (case ct
              (1  (enc 0)
                  (enc 1)
                  (setf (char str (+ 2 start)) #\=
                        (char str (+ 3 start)) #\=))
              (2  (enc 0)
                  (enc 1)
                  (enc 2)
                  (setf (char str (+ 3 start)) #\=)))
            (make-instance 'base64
                           :str str))
          )))))

(defmethod base64 ((x base64))
  x)

(defmethod base64 (x)
  (base64 (bev x)))

;; -------------------------------------------------------------

(defmethod hex ((x bev))
  (let* ((v   (bev-vec x))
         (nb  (length v))
         (str (make-string (* 2 nb))))
    (labels ((enc (val)
               (code-char
                (+ val
                   (if (< val 10)
                       (char-code #\0)
                     (- (char-code #\A) 10))))
               ))
    (loop for bx from (1- nb) downto 0
          for b = (aref v bx)
          for ix = (* 2 bx)
          do
          (setf (char str ix)      (enc (ldb (byte 4 4) b))
                (char str (1+ ix)) (enc (ldb (byte 4 0) b))))
    (make-instance 'hex
                   :str str))))

(defmethod hex ((x hex))
  x)

(defmethod hex (x)
  (hex (bev x)))

;; -------------------------------------------------------------

(defun sub-decode-58 (str)
  ;; decode big-endian base58 to integer value
  (let ((val  0))
    (loop for ix from (1- (length str)) downto 0
          for c = (char str ix)
          for v = (aref +inv-alphabet-58+ (char-code c))
          for base = 1 then (* base +len-58+)
          do
          (if (zerop v)
              (error "Invalid base58 string: ~S" str)
            (incf val (* base (1- v)))))
    val))

(defun convert-int-to-vec (val)
  ;; convert val to little-endian vector of UB8
  (let* ((nb (ceiling (integer-length val) 8))
         (v  (make-array nb
                         :element-type '(unsigned-byte 8))))
    (loop for ix from 0 below nb
          for pos from 0 by 8
          do
          (setf (aref v ix) (ldb (byte 8 pos) val)))
    v))

;; ------------------------------------------------------

(defmethod lev ((x lev))
  x)

(defmethod lev ((x bev))
  (make-instance 'lev
   :vec (reverse (bev-vec x))))

(defmethod lev ((val integer))
  (make-instance 'lev
   :vec (convert-int-to-vec val)))

(defmethod lev ((x base58))
  (let* ((str  (base58-str x))
         (nb   (sub-decode-58 (subseq str 0 6)))
         (nstr (length str))
         (vec  (make-array nb
                           :element-type '(unsigned-byte 8))))
    (um:nlet-tail iter ((start  6)
                        (vstart 0))
      (when (< start nstr)
        (let* ((end  (min nstr (+ start 700)))
               (vend (min nb (+ vstart 512)))
               (sub  (subseq str start end))
               (val  (sub-decode-58 sub)))
          (loop for ix from vstart below vend
                for pos from 0 by 8
                do
                (setf (aref vec ix) (ldb (byte 8 pos) val)))
          (iter end vend))))
    (make-instance 'lev
     :vec vec)))

(defmethod lev ((x base64))
  (let* ((str  (base64-str x))
         (nstr (length str))
         (vlen 0)
         (lst  nil))
    (um:nlet-tail iter ((start  0)
                        (val    0)
                        (ct     0))
      (labels ((decode (pos)
                 (push (ldb (byte 8 (* 8 (- 2 pos))) val) lst)
                 (incf vlen)))
        (when (>= ct 4)
          (decode 0)
          (decode 1)
          (decode 2)
          (setf val 0
                ct  0))
        (if (< start nstr)
            (let ((c (char str start)))
              (unless (char= c #\=)
                (let ((cv  (aref +inv-alphabet-64+ (char-code c))))
                  (when (zerop cv)
                    (error "Invalid Base64 string: ~S" str))
                  (setf val (dpb (1- cv) (byte 6 (* 6 (- 3 ct))) val))
                  (incf ct)))
              (iter (1+ start) val ct))
          ;; else
          (progn
            (case ct
              (2  (decode 0))
              (3  (decode 0)
                  (decode 1)))
            (make-instance 'lev
                           :vec (make-array (length lst)
                                            :element-type '(unsigned-byte 8)
                                            :initial-contents lst))
            ))))))

(defmethod lev ((x sequence))
  ;; LIST and VECTOR when can be coerced to UB8-VECTOR
  (make-instance 'lev
                 :vec (coerce x 'ub8-vector)))

(defmethod lev ((x ub8v-repr))
  (lev (ub8v-repr x)))

(defmethod lev ((x hex))
  ;; here it is known that HEX has a direct conversion from BEV
  (make-instance 'lev
                 :vec (nreverse
                       (bev-vec (bev x)))))

(defun levn (x nb)
  ;; create a LEV with a specified number of UB8 bytes
  (let* ((lev (lev x))
         (nel (length (lev-vec lev))))
    (cond ((< nel nb)
           ;; extend with zero filled tail
           (let* ((diff (- nb nel))
                  (tail (make-array diff
                                    :element-type '(unsigned-byte 8)
                                    :initial-element 0)))
             (make-instance 'lev
                            :vec (concatenate 'vector (lev-vec lev) tail))))
          ((> nel nb)
           ;; take from the LSB side
           (make-instance 'lev
                          :vec (subseq (lev-vec lev) 0 nb)))
          (t
           lev)
          )))

;; -----------------------------------------------------------

(defmethod bev ((x bev))
  x)

(defmethod bev ((x ub8v-repr))
  (bev (ub8v-repr x)))

(defmethod bev ((x lev))
  (make-instance 'bev
                 :vec (reverse (lev-vec x))))

(defmethod bev ((x sequence))
  ;; LIST and VECTOR when can be coerced to UB8-VECTOR
  (make-instance 'bev
                 :vec (coerce x 'ub8-vector)))

(defun nbev (x)
  ;; non-copying constructor - privately used when we have to first
  ;; convert to LEV
  (make-instance 'bev
                 :vec (nreverse (lev-vec (lev x)))))

(defmethod bev ((x integer))
  ;; INTEGER known to have LEV conversion
  (nbev x))

(defmethod bev ((x base58))
  ;; BASE58 known to have LEV conversion
  (nbev x))

(defmethod bev ((x base64))
  ;; BASE64 known to have LEV conversion
  (nbev x))

(defmethod bev ((x hex))
  (let* ((str  (hex-str x))
         (ns   (length str))
         (vec  (make-array (ceiling ns 2)
                           :element-type '(unsigned-byte 8))))
    (labels ((decode (ch)
               (cond ((char<= #\0 ch #\9) (- (char-code ch) #.(char-code #\0)))
                     ((char<= #\A ch #\F) (- (char-code ch) #.(- (char-code #\A) 10)))
                     ((char<= #\a ch #\f) (- (char-code ch) #.(- (char-code #\a) 10)))
                     (t
                      (error "Invalid Hex string: ~S" str))
                     )))
      (um:nlet-tail iter ((vx  0)
                          (sx  0)
                          (val 0)
                          (ct  0))
        (when (>= ct 2)
          (setf (aref vec vx) val
                ct  0
                val 0)
          (incf vx))
        (when (< sx ns)
          (iter vx (1+ sx)
                (+ (ash val 4)
                   (decode (aref str sx)))
                (1+ ct))))
      (make-instance 'bev
                     :vec vec))))

(defun bevn (x nb)
  ;; construct a BEV with a specified number of UB8 bytes
  (let* ((bev  (bev x))
         (nel  (length (bev-vec bev))))
    (cond ((< nel nb)
           ;; prepend with zero filled prefix
           (let* ((diff (- nb nel))
                  (pref (make-array diff
                                    :element-type '(unsigned-byte 8)
                                    :initial-element 0)))
             (make-instance 'bev
                            :vec (concatenate 'vector pref (bev-vec bev)))))
          ((> nel nb)
           ;; take a portion from the LSB side
           (make-instance 'bev
                          :vec (subseq (bev-vec bev) (- nel nb))))
          (t
           bev)
          )))

;; --------------------------------------------------------------
;; Integer conversions

(defmethod int ((x integer))
  x)

(defmethod int ((x lev))
  (convert-vec-to-int (lev-vec x)))

(defmethod int (x)
  (int (lev x)))

;; -------------------------------------------------------------------
;; Compare operators for trees and maps
;; Be careful of extremely large vectors... conversion to bignum

(defmethod ord:compare ((a ub8v) b)
  (ord:compare (int a) (int b)))

(defmethod ord:compare ((a ub8v-repr) b)
  (ord:compare (int a) (int b)))

