;;;
;;; Test net_oauth
;;;

(use gauche.test)

(test-start "net.oauth")

(use net.oauth)
(test-module 'net.oauth)


(test-end :exit-on-failure #t)
