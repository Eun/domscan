## domscan

Find alternative addresses for a domain

    go get github.com/Eun/domscan
---

    usage: domscan <options> host
            Options:
            start=0.0.0.0              scan from this ip range
            end=255.255.255.255        stop the scan at this ip range
            private=false              scan private ip addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            stop=true                  stop on first match
            tasks=10                   parallel tasks to use
            https=false                use https instead of http
            path=/                     path to use for compare
            timeout=1s                 timeout for hosts
            localaddr=                 local address to bind to (leave empty for default)
            compare=title              compare method (is a html document equal to another) (use a plausible jquery selector)
            useragent=                 user agent to use (leave empty for a random)



### Notes
* A scan can take a long time. Make sure you set the start and end values properly
* Some websites redirect to https, use the https option


MIT License
