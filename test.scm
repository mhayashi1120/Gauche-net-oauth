;;;
;;; Test net_oauth
;;;

(use gauche.test)

(test-start "net.oauth")
(use net.oauth)
(test-module 'net.oauth)

;; The following is a dummy test code.
;; Replace it for your tests.
;; (test* "test-net_oauth" "net_oauth is working"
;;        (test-net_oauth))

;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)




