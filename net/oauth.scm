;;;
;;; OAuth module
;;;

(define-module net.oauth
  (use rfc.http)
  (use rfc.sha)
  (use rfc.hmac)
  (use rfc.base64)
  (use rfc.uri)
  (use rfc.822)
  (use rfc.mime)
  (use srfi-1)
  (use srfi-13)
  (use www.cgi)
  (use math.mt-random)
  (use gauche.uvector)
  (use gauche.version)
  (use gauche.experimental.ref)         ; for '~'.  remove after 0.9.1
  (use text.tree)
  (use text.tr)
  (use util.list)
  (use util.match)
  (export 
   <oauth-cred>

   oauth-client-authenticator
   oauth-auth-header
   call/oauth
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
  `(,@params
    ("oauth_signature" ,(oauth-signature method request-url params
                                         consumer-secret token-secret))))

;; Calculate signature.
(define (oauth-signature method request-url params consumer-secret
                         :optional (token-secret ""))
  (base64-encode-string
   (hmac-digest-string (oauth-signature-base-string method request-url params)
                       :key #`",|consumer-secret|&,|token-secret|"
                       :hasher <sha1>)))

;; Construct signature base string. (Section 9.1)
(define (oauth-signature-base-string method request-url params)
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

(define (timestamp) (number->string (sys-time)))

(define oauth-nonce
  (let ([random-source (make <mersenne-twister>
                         :seed (* (sys-time) (sys-getpid)))]
        [v (make-u32vector 10)])
    (lambda ()
      (mt-random-fill-u32vector! random-source v)
      (digest-hexify (sha1-digest-string (x->string v))))))

;; Returns a header field suitable to pass as :authorization header
;; for http-post/http-get.
(define (oauth-auth-header method request-url params
                           consumer-key consumer-secret
                           access-token access-token-secret)
  (let* ([auth-params `(("oauth_consumer_key" ,consumer-key)
                        ("oauth_token" ,access-token)
                        ("oauth_signature_method" "HMAC-SHA1")
                        ("oauth_timestamp" ,(timestamp))
                        ("oauth_nonce" ,(oauth-nonce))
                        ("oauth_version" "1.0"))]
         [signature (oauth-signature
                     method request-url
                     `(,@auth-params ,@params)
                     consumer-secret
                     access-token-secret)])
    (format "OAuth ~a"
            (string-join (map (^p (format "~a=\"~a\"" (car p) (cadr p)))
                              `(,@auth-params
                                ("oauth_signature"
                                 ,(oauth-uri-encode signature))))
                         ", "))))

;;;
;;; Public API
;;;

(define (oauth-authenticate-consumer consumer-key consumer-secret)
  )

;;
;; Authenticate the client using OAuth PIN-based authentication flow.
;;

(define (oauth-client-authenticator request-url access-token-url authorize-url)

  (define (default-input-callback url)
    (print "Open the following url and type in the shown PIN.")
    (print url)
    (let loop ()
      (display "Input PIN: ") (flush)
      (let1 pin (read-line)
        (cond [(eof-object? pin) #f]
              [(string-null? pin) (loop)]
              [else pin]))))

  (lambda (consumer-key consumer-secret
                        :optional (input-callback default-input-callback))
    (let* ([r-response
            (oauth-request "GET" request-url
                           `(("oauth_consumer_key" ,consumer-key)
                             ("oauth_signature_method" "HMAC-SHA1")
                             ("oauth_timestamp" ,(timestamp))
                             ("oauth_nonce" ,(oauth-nonce))
                             ("oauth_version" "1.0"))
                           consumer-secret)]
           [r-token  (cgi-get-parameter "oauth_token" r-response)]
           [r-secret (cgi-get-parameter "oauth_token_secret" r-response)])
      (unless (and r-token r-secret)
        (error "failed to obtain request token"))
      (if-let1 oauth-verifier
          (input-callback
           #`",|authorize-url|?oauth_token=,|r-token|")
        (let* ([a-response
                (oauth-request "POST" access-token-url
                               `(("oauth_consumer_key" ,consumer-key)
                                 ("oauth_token" ,r-token)
                                 ("oauth_signature_method" "HMAC-SHA1")
                                 ("oauth_timestamp" ,(timestamp))
                                 ("oauth_nonce" ,(oauth-nonce))
                                 ("oauth_version" "1.0")
                                 ("oauth_verifier" ,oauth-verifier))
                               r-secret)]
               [a-token (cgi-get-parameter "oauth_token" a-response)]
               [a-secret (cgi-get-parameter "oauth_token_secret" a-response)])
          (make <oauth-cred>
            :consumer-key consumer-key
            :consumer-secret consumer-secret
            :access-token a-token
            :access-token-secret a-secret))
        #f))))

(define (call/oauth parser cred method path params . opts)
  (define (call)
    (if cred
      (let1 auth (oauth-auth-header
                  (if (eq? method 'get) "GET" "POST")
                  ;;TODO https?
                  #`"http://api.twitter.com,|path|" params
                  (~ cred'consumer-key) (~ cred'consumer-secret)
                  (~ cred'access-token) (~ cred'access-token-secret))
        (case method
          [(get) (apply http-get "api.twitter.com"
                        #`",|path|?,(oauth-compose-query params)"
                        :Authorization auth opts)]
          [(post) (apply http-post "api.twitter.com" path
                         (oauth-compose-query params)
                         :Authorization auth opts)]))
      (case method
        [(get) (apply http-get "api.twitter.com"
                      #`",|path|?,(oauth-compose-query params)" opts)]
        [(post) (apply http-post "api.twitter.com" path
                       (oauth-compose-query params) opts)])))

  (define (retrieve status headers body)
    (check-api-error status headers body)
    (values (parser body) headers))

  (call-with-values call retrieve))

(define (call/oauth-post-file->sxml cred path params . opts)

  (define (call)
    (let1 auth (oauth-auth-header
                "POST"
                ;;TODO https?
                #`"http://api.twitter.com,|path|" '()
                (~ cred'consumer-key) (~ cred'consumer-secret)
                (~ cred'access-token) (~ cred'access-token-secret))
      (hack-mime-composing 
       (apply http-post "api.twitter.com" path
              params
              :Authorization auth opts))))

  (define (retrieve status headers body)
    (check-api-error status headers body)
    (values (call-with-input-string body (cut ssax:xml->sxml <> '()))
            headers))

  (call-with-values call retrieve))

;;;
;;; Internal utilities
;;;

;; see `http-compose-form-data' comments
(define (param-form-data? param)
  (odd? (length param)))

(define (%-fix str)
  (regexp-replace-all* str #/%[\da-fA-F][\da-fA-F]/
                       (lambda (m) (string-upcase (m 0)))))

