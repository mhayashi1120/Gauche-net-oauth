;;;
;;; OAuth module
;;;

(define-module net.oauth
  (use rfc.http)
  (use rfc.sha)
  (use rfc.hmac)
  (use rfc.base64)
  (use rfc.uri)
  (use srfi-1)
  (use srfi-13)
  (use www.cgi)
  (use math.mt-random)
  (use gauche.uvector)
  (use gauche.version)
  (use gauche.experimental.ref)         ; for '~'.  remove after 0.9.1
  (use text.tree)
  (export 
   <oauth-cred>

   oauth-client-authenticator
   oauth-temporary-credential
   oauth-access-token
   oauth-authorize-constructor

   oauth-auth-header oauth-compose-query
   ))
(select-module net.oauth)

(define-class <oauth-cred> ()
  ((consumer-key :init-keyword :consumer-key)
   (consumer-secret :init-keyword :consumer-secret)
   (access-token :init-keyword :access-token)
   (access-token-secret :init-keyword :access-token-secret)))

;; todo http://tools.ietf.org/html/rfc5849

;; OAuth related stuff.
;; References to the section numbers refer to http://oauth.net/core/1.0/.

;; Returns query parameters with calculated "oauth_signature"
(define (oauth-add-signature method request-url params consumer-secret
                             :optional (token-secret ""))
  ;; Calculate signature.
  (define (signature method request-url params consumer-secret
                           :optional (token-secret ""))
    (base64-encode-string
     (hmac-digest-string (signature-base-string method request-url params)
                         :key #`",|consumer-secret|&,|token-secret|"
                         :hasher <sha1>)))

  `(,@params
    ("oauth_signature" ,(signature method request-url params
                                   consumer-secret token-secret))))

;; Construct signature base string. (Section 9.1)
(define (signature-base-string method request-url params)
  (define (param-sorter a b)
    (or (string<? (car a) (car b))
        (and (string=? (car a) (car b))
             (string<? (cadr a) (cadr b)))))
  (let1 normalize-params (sort (remove param-form-data? params) param-sorter)
    (string-append
     (string-upcase method) "&"
     (oauth-uri-encode (oauth-normalize-request-url request-url)) "&"
     (oauth-uri-encode (oauth-compose-query normalize-params)))))

;; Oauth requires hex digits in %-encodings to be upper case (Section 5.1)
;; The following two routines should be used instead of uri-encode-string
;; and http-compose-query to conform that.
(define (oauth-uri-encode str)
  (%-fix (uri-encode-string str :encoding 'utf-8)))

(define (oauth-compose-query params)
  (define (only-query-string? list)
    (or (null? list)
        (and (not (param-form-data? (car list)))
             (only-query-string? (cdr list)))))

  (if (only-query-string? params)
    (%-fix (http-compose-query #f params 'utf-8))
    (http-compose-form-data params #f 'utf-8)))

;;TODO 5.4.2 WWW-Authenticate

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

;; Reqest either request token or access token.
(define (oauth-request method request-url params consumer-secret
                       :optional (token-secret ""))
  (define (add-sign meth)
    (oauth-add-signature meth request-url params consumer-secret token-secret))
  (receive (scheme specific) (uri-scheme&specific request-url)
    ;; https is supported since 0.9.1
    (define secure-opt
      (cond [(equal? scheme "http") '()]
            [(equal? scheme "https")
             (if (version>? (gauche-version) "0.9") `(:secure #t) '())]
            [else (error "oauth-request: unsupported scheme" scheme)]))
    (receive (auth path query frag) (uri-decompose-hierarchical specific)
      (receive (status header body)
          (cond [(equal? method "GET")
                 (apply http-get auth
                        #`",|path|?,(oauth-compose-query (add-sign \"GET\"))"
                        secure-opt)]
                [(equal? method "POST")
                 (apply http-post auth path
                        (oauth-compose-query (add-sign "POST"))
                        secure-opt)]
                [else (error "oauth-request: unsupported method" method)])
        (unless (equal? status "200")
          (errorf "oauth-request: service provider responded ~a: ~a"
                  status body))
        (cgi-parse-parameters :query-string body)))))

;; Returns a header field suitable to pass as :authorization header
;; for http-post/http-get.
(define (oauth-auth-header method request-url params cred)
  (let ([auth-params `(("oauth_consumer_key" ,(~ cred'consumer-key))
                       ("oauth_token" ,(~ cred'access-token))
                       ("oauth_signature_method" "HMAC-SHA1")
                       ("oauth_timestamp" ,(timestamp))
                       ("oauth_nonce" ,(oauth-nonce))
                       ("oauth_version" "1.0"))])
    (format "OAuth ~a"
            (string-join (map 
                          (^p 
                           (let ((k (car p))
                                 (v (cadr p)))
                             #`",|k|=\",|v|\""))
                          (oauth-add-signature 
                           method request-url auth-params
                           (~ cred'consumer-secret) (~ cred'access-token-secret)))
                         ", "))))

;;;
;;; Public API
;;;

;;
;; Authenticate the client using OAuth PIN-based authentication flow.
;;

(define (oauth-client-authenticator request-sender authorizer)

  (lambda (consumer-key consumer-secret input-callback)
    (receive (r-token r-secret)
        (request-sender consumer-key consumer-secret)
      (if-let1 oauth-verifier
          (input-callback r-token)
        (receive (a-token a-secret)
            (authorizer 
             consumer-key oauth-verifier
             r-token r-secret)
          (make <oauth-cred>
            :consumer-key consumer-key
            :consumer-secret consumer-secret
            :access-token a-token
            :access-token-secret a-secret))
        #f))))

(define (oauth-temporary-credential request-url)
  (lambda (consumer-key consumer-secret)
    (let* ([r-response
            (oauth-request "GET" request-url
                           `(("oauth_consumer_key" ,consumer-key)
                             ("oauth_nonce" ,(oauth-nonce))
                             ("oauth_signature_method" "HMAC-SHA1")
                             ("oauth_timestamp" ,(timestamp))
                             ("oauth_version" "1.0"))
                           consumer-secret)]
           [r-token  (cgi-get-parameter "oauth_token" r-response)]
           [r-secret (cgi-get-parameter "oauth_token_secret" r-response)])
      (unless (and r-token r-secret)
        (error "failed to obtain request token"))
      (values r-token r-secret))))

(define (oauth-authorize-constructor authorize-url)
  (lambda (oauth-token :key (oauth-callback #f)
                       :allow-other-keys params)
    (when (odd? (length params))
      (error "Keywords are not even."))
    (let1 query 
        (compose-query 
         `(
           ("oauth_token" ,oauth-token)
           ,@(if oauth-callback `(("oauth_callback" ,oauth-callback)) '())
           ,@(let loop ((params params)
                        (res '()))
               (if (null? params)
                 (reverse res)
                 (let ((k (car params))
                       (v (cadr params)))
                   (loop (cddr params) 
                         (cons 
                          `(,(x->string k) ,(x->string v))
                          res)))))))
      #`",|authorize-url|?,|query|")))

(define (oauth-access-token authorize-url)
  (lambda (c-key verifier r-token r-secret)
    (let* ([a-response
            (oauth-request "POST" authorize-url
                           `(("oauth_consumer_key" ,c-key)
                             ("oauth_nonce" ,(oauth-nonce))
                             ("oauth_signature_method" "HMAC-SHA1")
                             ("oauth_timestamp" ,(timestamp))
                             ("oauth_token" ,r-token)
                             ("oauth_verifier" ,verifier)
                             ("oauth_version" "1.0"))
                           r-secret)]
           [a-token (cgi-get-parameter "oauth_token" a-response)]
           [a-secret (cgi-get-parameter "oauth_token_secret" a-response)])
      (unless (and a-token a-secret)
        (error "failed to obtain access token"))
      (values a-token a-secret))))

;;;
;;; Internal utilities
;;;

(define (timestamp) (number->string (sys-time)))

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

;; 5.1.  Parameter Encoding
(define (%-fix str)
  (regexp-replace-all* str #/%[\da-fA-F][\da-fA-F]/
                       (lambda (m) (string-upcase (m 0)))))

(define (compose-query params)
  (%-fix (http-compose-query #f params 'utf-8)))


