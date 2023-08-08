# gospoofcheck
A Go copy of the original spoofcheck written by BishopFox:
https://github.com/BishopFox/spoofcheck/tree/master

also had to copy / re-write this library:
https://github.com/lunarca/pyemailprotectionslib/tree/master/emailprotectionslib

A program that checks if a domain can be spoofed from. The program checks SPF and DMARC records for weak configurations that allow spoofing.

Additionally it will alert if the domain has DMARC configuration that sends mail or HTTP requests on failed SPF/DKIM emails.

Domains are spoofable if any of the following conditions are met:
- Lack of an SPF or DMARC record
- SPF record never specifies `~all` or `-all`
- DMARC policy is set to `p=none` or is nonexistent
