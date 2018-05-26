;;;; address.lisp

(in-package :cosi/proofs)



;;;; Addresses: Public Key Hashes in Emotiq

;;; Hashed public keys are almost always presented as addresses, and such an
;;; `address' for a public key is in general produced as follows:
;;;
;;; First, it is hashed in such a way that collisions are considered to have
;;; negligible probability and to be irreversible, and then encoded in a user
;;; friendly manner.  That is, shorter; with characters easily typed and read
;;; and distinguishable by humans in nearly all computing environments; with at
;;; least simple checksum-type checking available; and with a version prefix
;;; (which also helps identify which cryptocurrency it's for).  To achieve this,

;;; It seems we can, as many other cryptocurrencies have done, simply adopt the
;;; Bitcoin specification for addresses, and then just use a unique version
;;; prefix.

;;; In Bitcoin the details are as follows. For the first hash we use
;;; SHA2/256. For the shortening second hash we use RIPEMD160, cutting the
;;; number of bits down to 160.  For checksum, we use Bitcoin's technique: use
;;; the first four octets of the result of a double SHA2/256 hash of the
;;; sequence (version prefix + data), and this gets tacked on to the end of the
;;; of the version prefix + data sequence to give us our final result: a
;;; Base58check-encoded address.

;;; In a less abstract and more concrete sense, here is what we do right now:
;;;
;;;   Public Key => SHA-2/256 => RIPEMD160 => Base58Check Encode w/#xEA version prefix

(defparameter *mainnet-version-for-public-key-to-address* #xEA ; 234
  "An byte octet thats serves as a version prefix for mainnet public key hash
   address creation.")

(defparameter *testnet-version-for-public-key-to-address* #xEB ; 235
  "An byte octet thats serves as a version prefix for testnet public key hash
   address creation.")

;; NOTE: the mainnet version is the preferred/default version below.


(defparameter *base-58-alphabet-string*
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(assert (= (length *base-58-alphabet-string*) 58))

(defun map-to-base58-char (octet)
  (char *base-58-alphabet-string* octet))

(defun octet-vector-to-integer-value (octet-vector)
  (loop with integer-value = 0
        for i from (1- (length octet-vector)) downto 0
        as j from 0
        do (setq integer-value
                 (+ integer-value 
                    (ash (aref octet-vector i)
                         (* j 8))))
        finally (return integer-value)))

;; Efficiency note: with the above integer-value always in practice becomes a
;; bignum. Were this used for large octet vectors, this would ephemerally cons
;; up the proverbial wazoo. Are all compilers these days are "sufficiently
;; smart" about handling that?  Maybe not, but it fortunately doesn't matter in
;; this case, since this here exclusively used for fixed-length, relatively
;; small, byte vectors. -mhd, 5/26/18

(defun b58 (octet-vector)
  (loop with x = (octet-vector-to-integer-value octet-vector)
        with remainder
        with n-leading-null-bytes
          = (loop for i from 0 below (length octet-vector)
                  while (zerop (aref octet-vector i))
                  count t)
        with string-outstream = (make-string-output-stream)
        while (> x 0)
        do (multiple-value-setq (x remainder) (floor x 58))
           (write-char (map-to-base58-char remainder) string-outstream)
        finally
           (loop repeat n-leading-null-bytes
                 do (write-char (map-to-base58-char 0) string-outstream))
           (return
             (nreverse
              (get-output-stream-string string-outstream)))))



  

(defun public-key-to-address (public-key &key net override-version)
  "Produce an address for PUBLIC-KEY. Keyword :NET can be either :MAIN (default)
   for mainnet or :TEST for testnet.  The version prefix is usually determined
   by the net. However, if OVERRIDE-VERSION is specified non-nil, it should be a
   version prefix octet to be used, and in that case it is used instead. This is
   intended to be used as a testing and debugging feature."
  (let* ((sha2/256 (print (hash:hash/sha2/256 public-key)))
         (ripemd/160 (print (hash:hash/ripemd/160 sha2/256)))
         (data-vec (print (vec-repr:bev-vec ripemd/160)))
         (version-octet
           (or override-version
               (ecase net
                 ((nil :main) *mainnet-version-for-public-key-to-address*)
                 (:test *testnet-version-for-public-key-to-address*))))
         (prefix-vec
           (vec-repr:make-ub8-vector 1 :initial-element version-octet))
         (prefix+data
           (concatenate 'ub8-vector prefix-vec data-vec))
         (checksum-vec
           ;; first 4 bytes of the double sha2/256 hash of prefix+data
           (subseq (vec-repr:bev-vec
                    (hash:hash/sha2/256 (hash:hash/sha2/256 prefix+data)))
                   0 4))
         ;; tack that checksum onto the end of the prefix+data
         (prefix+data+checksum
           (concatenate 'ub8-vector prefix+data checksum-vec)))
    ;; return result encoded in base 58
    (b58 prefix+data+checksum)))

;; Note: the :override-version keyword lets you take a public key and version
;; prefix and test results from any crypto currency and compare results.
;;
;; E.g., you can use this with address tester here:
;;
;;   http://gobittest.appspot.com/Address
;;
;; E.g., you can copy/paste what's in 1 - Public ECDSA Key into a Lisp string *S*,
;; and then you can do
;;
;;   (public-key-to-address (ironclad:hex-string-to-byte-array *s*) :override-version 0)
;;
;; Try with *s* = "0433F8C523B3FF52F0A515DD19EB88B1356BED642F5B9A55AE34D7481FE2EED2D36BDACAFD1A400910CDD1F3BB79A8C4D090C37180156BE25D2801D53DFA646066"
;; Result should be: "1ABD7Te3tqtMmdmYh432fSyB2fX3juS475"
;;
;; You can also put the above (or some other) public key into the blank at the
;; test site and click "send" to verify that it gets the same result.
            



;; Useful reference: a survey of various cryptocurrencies and their address formats
;; 
;;   https://blockgeeks.com/guides/blockchain-address-101/

;; Here's what they are for Bitcoin:
;;
;; Bitcoin Address: 0x00
;; Pay to Script Hash address: 3
;; Bitcoin testnet address: 0x6F
;; Private key WIF: 0x80
;; BIP-38 Encrypted private key: 0x0142
;;
;; Here's a longer exhaustive list:
;; https://en.bitcoin.it/wiki/List_of_address_prefixes

;; Bitcoin reference on Base 58:
;;
;;   https://en.bitcoin.it/wiki/Base58Check_encoding#Creating_a_Base58Check_string

;; Note: there could be a positive reason to AVOID being actually identical
;; with a Bitcoin address in all details. That's because it can cause
;; confusion.  In this article about Litecoin's new "M-address" format, they
;; talk about how they are introducing the prefix "M" for addresses, replacing
;; the prefix "3", just to be different from Bitcoin to avoid confusion. Here's
;; the article:
;; https://blog.trezor.io/litecoins-new-p2sh-segwit-addresses-843633e3e707
;;
;; I guess the way to fit into this community would be to get our own prefix.

;; We believe it's semi-accepted practice to use Bitcoin's format but to make
;; up your own prefix for non-bitcoin users of Bitcoin's Base 58 format, and so
;; that is what we do.

;; [The above is open to review and criticism, especially during our early
;; testnet period.] -mhd, 5/26/18
