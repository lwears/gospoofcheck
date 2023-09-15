package spf

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/lwears/gospoofcheck/emailprotections/shared"
	"github.com/miekg/dns"
)

type SpfRecord struct {
	Version        string
	Record         string
	Mechanisms     []string
	AllString      string
	Domain         string
	RecursionDepth int8
}

func FromDomain(opts *shared.Options) (*SpfRecord, error) {
	spfString, err := GetSpfStringForDomain(opts)
	if err != nil {
		return nil, fmt.Errorf("error getting spf string for domain %s", err)
	}

	return FromSpfString(spfString, opts.Domain)
}

func FromSpfString(spfString *string, domain string) (*SpfRecord, error) {
	if spfString == nil {
		return &SpfRecord{Domain: domain}, nil
	}

	mechanisms := extractMechanisms(*spfString)

	return &SpfRecord{
		Domain:     domain,
		Record:     *spfString,
		Mechanisms: mechanisms,
		Version:    extractVersion(*spfString),
		AllString:  extractAllMechanism(mechanisms),
	}, nil
}

func GetSpfStringForDomain(opts *shared.Options) (*string, error) {
	if !shared.IsValidDomainName(opts.Domain) {
		return nil, shared.InvalidDomainError
	}

	fqnd := dns.Fqdn(opts.Domain)
	m := dns.Msg{}
	m.SetQuestion(fqnd, dns.TypeTXT)
	m.RecursionDesired = true
	// Whatever this is fixed it
	m.SetEdns0(4096, false)
	r, err := dns.Exchange(&m, opts.DnsResolver)
	if err != nil {
		return nil, err
	}

	result := findSpfStringFromAnswers(r.Answer)

	return result, nil
}

// func (spf *SpfRecord) GetRedirectedRecord() string {
// 	if spf.RecursionDepth >= 10 {
// 		return spf.GetRedirectDomain()
// 	} else {
// 		rd := spf.GetRedirectDomain()
// 		if rd != "" {
// 			rd = FromDomain(rd)

// 		}
// 	}
// }

func (spf *SpfRecord) GetRedirectDomain() string {
	if len(spf.Mechanisms) > 0 {
		for _, m := range spf.Mechanisms {
			matches := regexp.MustCompile("redirect=(.*)").FindStringSubmatch(m)
			if len(matches) >= 1 {
				return matches[1]
			}
		}
	}
	return ""
}

func (spf *SpfRecord) IsRedirectMechanismStrong(dnsResolver string) (bool, error) {
	if redirectDomain := spf.GetRedirectDomain(); redirectDomain != "" {
		redirectDomainSpf, err := FromDomain(&shared.Options{DnsResolver: dnsResolver, Domain: redirectDomain})
		if err != nil {
			return false, fmt.Errorf("error fetching redirect domain %s", err)
		}
		isRedirectDomainSpfStrong, err := redirectDomainSpf.IsRecordStrong(&shared.Options{DnsResolver: dnsResolver})
		if err != nil {
			return false, fmt.Errorf("error checking redirect domains spf %s", err)
		}

		return redirectDomainSpf != nil && isRedirectDomainSpfStrong, nil
	}

	return false, nil
}

func (spf *SpfRecord) IsRecordStrong(opts *shared.Options) (bool, error) {
	allStrength := spf.IsAllMechanismStrong()

	redirectStrength, err := spf.IsRedirectMechanismStrong(opts.DnsResolver)
	if err != nil {
		return false, fmt.Errorf("error checking redirect mechanism %s", err)
	}

	includeStrength, err := spf.AreIncludeMechanismsStrong(opts)
	if err != nil {
		return false, fmt.Errorf("error checking include mechanisms %s", err)
	}

	return allStrength && redirectStrength && includeStrength, nil
}

func (spf *SpfRecord) IsAllMechanismStrong() bool {
	return slices.Contains([]string{"~all", "-all"}, spf.AllString)
}

func (spf *SpfRecord) AreIncludeMechanismsStrong(opts *shared.Options) (bool, error) {
	includeRecords, err := spf.GetIncludeRecords(opts.DnsResolver)
	if err != nil {
		return false, fmt.Errorf("error fetching include record spf %s", err)
	}
	for _, r := range includeRecords {
		if _, ok := includeRecords[r.Domain]; ok {
			return includeRecords[r.Domain].IsRecordStrong(opts)
		}
	}
	return false, nil
}

func (spf *SpfRecord) GetIncludeDomains() []string {
	includeDomains := make([]string, 0)
	if len(spf.Mechanisms) > 0 {
		for _, m := range spf.Mechanisms {
			includeMechanism := regexp.MustCompile(`include:(\S+)`).FindStringSubmatch(m)
			if len(includeMechanism) >= 1 {
				includeDomains = append(includeDomains, includeMechanism[1])
			}
		}
	}
	return includeDomains
}

func (spf *SpfRecord) GetIncludeRecords(dnsResolver string) (map[string]*SpfRecord, error) {
	start := make(map[string]*SpfRecord)

	if spf.RecursionDepth >= 10 {
		return start, nil
	} else {
		includeDomains := spf.GetIncludeDomains()
		for _, domain := range includeDomains {
			var err error
			start[domain], err = FromDomain(&shared.Options{Domain: domain, DnsResolver: dnsResolver})
			if err != nil {
				return nil, fmt.Errorf("error fetching include record spf %s", err)
			}
			start[domain].RecursionDepth = spf.RecursionDepth
		}
	}
	return start, nil
}

func findSpfStringFromAnswers(txtRecords []dns.RR) *string {
	for _, a := range txtRecords {
		if x, ok := a.(*dns.TXT); ok {
			// If spf is longer than 255 bytes its split into multiple strings
			if len(x.Txt) > 1 {
				x.Txt = []string{strings.Join(x.Txt, "")}
			}
			for _, t := range x.Txt {
				if strings.Contains(t, "v=spf1") {
					return &t
				}
			}
		}
	}
	return nil
}

func extractMechanisms(spfString string) []string {
	spfMechanismPattern := regexp.MustCompile(`(?:((?:\+|-|~)?(?:a|mx|ptr|include|ip4|ip6|exists|redirect|exp|all)(?:(?::|=|/)?(?:\S*))?) ?)`)
	return spfMechanismPattern.FindAllString(spfString, -1)
}

func extractVersion(spfString string) string {
	spfVersionPattern := regexp.MustCompile("^v=(spf.)")
	spfVersion := spfVersionPattern.FindString(spfString)
	return spfVersion
}

func extractAllMechanism(mechanisms []string) string {
	allMachanism := ""
	for _, m := range mechanisms {
		if m == regexp.MustCompile(".*all.*").FindString(m) {
			allMachanism = strings.TrimSpace(m)
		}
	}
	return allMachanism
}
