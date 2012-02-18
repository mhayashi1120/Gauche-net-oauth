;;;
;;; Test net.oauth
;;;

(add-load-path ".")

(use gauche.test)

(test-start "net.oauth")
(use net.oauth)
(test-module 'net.oauth)

(test-end)





