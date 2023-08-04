package emailprotections

import (
	"regexp"
	"strings"
)

const (
	domainNamePattern = `^([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*[\._]?$`
	httpPrefix        = "http://"
	httpsPrefix       = "https://"
)

func IsValidDomainName(domain string) bool {
	if len(strings.TrimSpace(domain)) < 1 {
		return false
	}
	regex := regexp.MustCompile(domainNamePattern)
	return regex.MatchString(domain)
}
