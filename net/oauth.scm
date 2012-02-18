;;;
;;; OAuth module
;;;

(define-module net.oauth
  (use util.list)
  (use rfc.http)
  (use rfc.sha)
  (use rfc.hmac)
  (use rfc.base64)
  (use rfc.uri)
  (use srfi-1)
  (use srfi-13)
  (use www.cgi)
  (use math.mt-random)
  (use gauche.parameter)
  (use gauche.uvector)
  (use gauche.version)
  (use gauche.experimental.ref)         ; for '~'.  remove after 0.9.1
  (use text.tree)
  (export 
   <oauth-cred>

   oauth-temporary-credential
   oauth-credential
   oauth-authorize-constructor

   oauth-auth-header oauth-compose-query
   ))
(select-module net.oauth)

;; Contain a authorize information about OAuth.
;; Extend the class if there are any Additional parameters. (Section 7)
(define-class <oauth-cred> ()
  ((consumer-key :init-keyword :consumer-key)
   (consumer-secret :init-keyword :consumer-secret)
   (access-token :init-keyword :access-token)
   (access-token-secret :init-keyword :access-token-secret)
   (additional-parameters :init-keyword :additional-parameters)))

;; http://tools.ietf.org/html/rfc5849

;; OAuth related stuff.
;; References to the section numbers refer to http://oauth.net/core/1.0/

;;TODO RSA-SHA1
(define oauth-signature-method
  (make-parameter 'hmac-sha1))

;; Signing Request (Section 9)
;; Returns query calculated "oauth_signature" parameter.
(define (oauth-signature method request-url oauth params consumer-secret token-secret)
  ;; Calculate signature.
  (define (signature)
    (let1 normalized `(,@(oauth-params) 
                       ,@(url-encoded-params))
      (base64-encode-string
       (hmac-digest-string (signature-base-string method request-url normalized)
                           :key #`",|consumer-secret|&,|token-secret|"
                           :hasher <sha1>))))

  (define (oauth-params)
    (filter (^x (string-prefix? "oauth_" (car x))) oauth))

  (define (url-encoded-params)
    (if (enable-urlencoded? params)
      params
      '()))

  `("oauth_signature" ,(signature)))

;; Construct signature base string. (Section 9.1)
(define (signature-base-string method request-url params)
  (let1 normalized (oauth-normalize-parameters params)
    (string-append
     (string-upcase method) "&"
     (oauth-uri-encode (oauth-normalize-request-url request-url)) "&"
     (oauth-uri-encode (oauth-compose-query normalized)))))

;; Normalize Request Parameters (Section 9.1.1)
(define (oauth-normalize-parameters params)
  (define (param-sorter a b)
    (or (string<? (car a) (car b))
        (and (string=? (car a) (car b))
             (string<? (cadr a) (cadr b)))))
  (sort (remove param-form-data? params) param-sorter))

;; Normalize request url.  (Section 9.1.2)
(define (oauth-normalize-request-url url)
  (receive (scheme userinfo host port path query frag) (uri-parse url)
    (tree->string `(,(string-downcase scheme) "://"
                    ,(if userinfo `(,(string-downcase userinfo) "@") "")
                    ,(string-downcase host)
                    ,(if (or (not port)
                             (and (string-ci=? scheme "http")
                                  (equal? port "80"))
                             (and (string-ci=? scheme "https")
                                  (equal? port "443")))
                       ""
                       `(":" ,port))
                    ,path))))

;; Oauth requires hex digits in %-encodings to be upper case (Section 5.1)
;; The following two routines should be used instead of uri-encode-string
;; and http-compose-query to conform that.
(define (oauth-uri-encode str)
  (%-fix (uri-encode-string str :encoding 'utf-8)))

(define (oauth-compose-query params)
  (if (enable-urlencoded? params)
    (%-fix (http-compose-query #f params 'utf-8))
    (http-compose-form-data params #f 'utf-8)))

;;TODO 5.4.2 WWW-Authenticate

;; Reqest either request token or access token.
(define (oauth-request method request-url oauth-params params consumer-secret
                       :optional (token-secret "") (auth #f))
  (define (add-sign meth)
    (let1 sign (oauth-signature meth request-url oauth-params params
                                consumer-secret token-secret)
      `(,@oauth-params ,@params ,sign)))

  (receive (scheme specific) (uri-scheme&specific request-url)
    ;; https is supported since 0.9.1
    (define secure
      (cond [(equal? scheme "http") #f]
            [(equal? scheme "https")
             (if (version>? (gauche-version) "0.9") #t #f)]
            [else (error "oauth-request: unsupported scheme" scheme)]))
    (receive (host path query frag) (uri-decompose-hierarchical specific)
      (receive (status header body)
          (cond [(equal? method "GET")
                 (http-get host
                           #`",|path|?,(oauth-compose-query (add-sign \"GET\"))"
                           :Authorization auth
                           :secure secure)]
                [(equal? method "POST")
                 (http-post host path
                            (oauth-compose-query (add-sign "POST"))
                            :Authorization auth
                            :secure secure)]
                [else (error "oauth-request: unsupported method" method)])
        (unless (equal? status "200")
          (errorf "oauth-request: service provider responded ~a: ~a"
                  status body))
        (cgi-parse-parameters :query-string body)))))

;;;
;;; Public API
;;;

;; Section 5.4.1: Authorization Header
;; Returns a header field suitable to pass as :authorization header
;; for http-post/http-get.
(define (oauth-auth-header method request-url params cred :optional (realm #f))
  (let* ([o-params `(,@(if realm '(("realm" realm)) '())
                     ("oauth_consumer_key" ,(~ cred'consumer-key))
                     ("oauth_nonce" ,(oauth-nonce))
                     ("oauth_signature_method" ,(signature-method-string))
                     ("oauth_timestamp" ,(timestamp))
                     ("oauth_token" ,(~ cred'access-token))
                     ("oauth_version" "1.0"))]
         [sign (oauth-signature method request-url o-params params
                                (~ cred'consumer-secret) (~ cred'access-token-secret))]
         [auth (map 
                (^p 
                 (let ((k (car p))
                       (v (cadr p)))
                   #`",(oauth-uri-encode k)=\",(oauth-uri-encode v)\""))
                `(,@o-params ,sign))])
    (format "OAuth ~a" (string-join auth ", "))))

;; Obtaining an Unauthorized Request Token (Section 6.1)
;; Return procedure's signature is
;;
;;     consumer-key -> consumer-secret -> <oauth-cred>
;;
;;  Additional parameters returns parsed as `cgi-parse-parameters'
;;  :class is extended class of <oauth-cred>
(define (oauth-temporary-credential request-url 
                                    :key (class <oauth-cred>))
  (lambda (consumer-key consumer-secret :optional (params '()))
    (let* ([r-response
            (oauth-request "GET" request-url
                           `(("oauth_consumer_key" ,consumer-key)
                             ("oauth_nonce" ,(oauth-nonce))
                             ("oauth_signature_method" ,(signature-method-string))
                             ("oauth_timestamp" ,(timestamp))
                             ("oauth_version" "1.0"))
                           params consumer-secret)]
           [r-token  (cgi-get-parameter "oauth_token" r-response)]
           [r-secret (cgi-get-parameter "oauth_token_secret" r-response)]
           [additionals (remove-params '("oauth_token" "oauth_token_secret")
                                       r-response)])
      (unless (and r-token r-secret)
        (error "failed to obtain request token"))
      (make class
        :consumer-key consumer-key
        :consumer-secret consumer-secret
        :access-token r-token
        :access-token-secret r-secret
        :additional-parameters additionals))))

(define (oauth-authorize-constructor authorize-url)
  (lambda (temp-cred :key (oauth-callback #f)
                     :allow-other-keys params)
    (when (odd? (length params))
      (error "Keywords are not even."))
    (let1 params (let loop ((params params)
                            (res '()))
                   (if (null? params)
                     (reverse res)
                     (let ((k (car params))
                           (v (cadr params)))
                       (loop (cddr params) 
                             (cons 
                              `(,(x->string k) ,(x->string v))
                              res)))))
      (oauth-construct-authorize-url 
       authorize-url
       :oauth-token (~ temp-cred'access-token)
       :oauth-callback oauth-callback
       :params params))))

;; Consumer Directs the User to the Service Provider (Section 6.2.1)
(define (oauth-construct-authorize-url url
                                       :key (oauth-token #f) (oauth-callback #f)
                                       (params '()))
  (let1 query 
      (compose-query
       `(,@(cond-list
            [oauth-token `("oauth_token" ,oauth-token)]
            [oauth-callback `("oauth_callback" ,oauth-callback)])
         ,@params))
    #`",|url|?,|query|"))

;; Obtaining an Access Token (Section 6.3)
;; Returns multiple values 
;;  The Access Token, The Token Secret and Additional parameters.
;;  Additional parameters returns parsed as `cgi-parse-parameters'
;; keyword args are same as oauth-temporary-credential
(define (oauth-credential authorize-url :key (class <oauth-cred>))
  (lambda (temp-cred verifier :optional (params '()))
    (let* ([auth (oauth-auth-header "POST" authorize-url params temp-cred)]
           [a-response
            (oauth-request "POST" authorize-url
                           `(("oauth_consumer_key" ,(~ temp-cred'consumer-key))
                             ("oauth_nonce" ,(oauth-nonce))
                             ("oauth_signature_method" ,(signature-method-string))
                             ("oauth_timestamp" ,(timestamp))
                             ("oauth_token" ,(~ temp-cred'access-token))
                             ("oauth_verifier" ,verifier)
                             ("oauth_version" "1.0"))
                           params
                           (~ temp-cred'consumer-secret)
                           (~ temp-cred'access-token-secret) auth)]
           [a-token (cgi-get-parameter "oauth_token" a-response)]
           [a-secret (cgi-get-parameter "oauth_token_secret" a-response)]
           [additionals (remove-params '("oauth_token" "oauth_token_secret")
                                       a-response)])
      (unless (and a-token a-secret)
        (error "failed to obtain access token"))
      (make class
        :consumer-key (~ temp-cred'consumer-key)
        :consumer-secret (~ temp-cred'consumer-secret)
        :access-token a-token
        :access-token-secret a-secret
        :additional-parameters additionals))))

;;;
;;; Internal utilities
;;;

;; Timestamp (Section 8)
(define (timestamp) (number->string (sys-time)))

;; Nonce (Section 8)
(define oauth-nonce
  (let ([random-source (make <mersenne-twister>
                         :seed (* (sys-time) (sys-getpid)))]
        [v (make-u32vector 10)])
    (lambda ()
      (mt-random-fill-u32vector! random-source v)
      (digest-hexify (sha1-digest-string (x->string v))))))

;; see `http-compose-form-data' comments
(define (param-form-data? param)
  (odd? (length param)))

(define (enable-urlencoded? params)
  (or (null? params)
      (and (not (param-form-data? (car params)))
           (enable-urlencoded? (cdr params)))))

;; 5.1.  Parameter Encoding
(define (%-fix str)
  (regexp-replace-all* str #/%[\da-fA-F][\da-fA-F]/
                       (lambda (m) (string-upcase (m 0)))))

(define (compose-query params)
  (%-fix (http-compose-query #f params 'utf-8)))

(define (remove-params names parameters)
  (if (null? names)
    parameters
    (remove-params
     (cdr names)
     (remove (^x (string=? (car x) (car names))) parameters))))

(define (signature-method-string)
  (case (oauth-signature-method)
    ((hmac-sha1) "HMAC-SHA1")
    (else
     (error "Unsupported method" (oauth-signature-method)))))

