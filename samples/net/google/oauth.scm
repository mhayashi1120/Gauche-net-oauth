(define-module net.google.oauth
  (use net.oauth)
  (use www.cgi)
  (export
   google-oauth-request-token
   google-oauth-authorize-url
   google-oauth-access-token)

  )
(select-module net.google.oauth)


(define-class <google-cred> (<oauth-cred>)
  (%scopes  :init-value ()))

(define-method google-oauth-request-token (consumer secret (scopes <pair>))
  (let1 proc (oauth-temporary-credential "https://www.google.com/accounts/OAuthGetRequestToken"
                                         :class <google-cred>)
    (rlet1 cred (proc consumer secret `(("scope" ,(string-join scopes " "))))
      (slot-set! cred '%scopes scopes))))

(define-method google-oauth-request-token (consumer secret (scope <string>))
  (google-oauth-request-token consumer secret (string-split scope " ")))

(define google-oauth-authorize-url
  (oauth-authorize-constructor "https://www.google.com/accounts/OAuthAuthorizeToken"))

(define (google-oauth-access-token request-token verifier)
  (let1 proc (oauth-credential "https://www.google.com/accounts/OAuthGetAccessToken"
                               :class <google-cred>)
    (proc request-token verifier)))


