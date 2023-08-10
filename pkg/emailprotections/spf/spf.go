package spf

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/lwears/gospoofcheck/pkg/emailprotections/shared"
	"github.com/miekg/dns"
)

const rootDomain = "@"

var NoSpfFoundError = errors.New("No SPF string found for domain")

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

	return FromSpfString(spfString, &opts.Domain)
}

func FromSpfString(spfString *string, domain *string) (*SpfRecord, error) {
	if spfString == nil {
		return nil, errors.New("no spf string")
	}

	mechanisms := ExtractMechanisms(*spfString)

	return &SpfRecord{
		Domain:     *domain,
		Record:     *spfString,
		Mechanisms: mechanisms,
		Version:    ExtractVersion(*spfString),
		AllString:  ExtractAllMechanism(mechanisms),
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

	result := FindSpfStringFromAnswers(r.Answer)

	return result, nil
}

func FindSpfStringFromAnswers(txtRecords []dns.RR) *string {
	for _, a := range txtRecords {
		x := a.(*dns.TXT)
		for _, t := range x.Txt {
			if strings.Contains(t, "v=spf1") {
				return &t
			}
		}
	}
	return nil
}

func ExtractMechanisms(spfString string) []string {
	spfMechanismPattern := regexp.MustCompile(`(?:((?:\+|-|~)?(?:a|mx|ptr|include|ip4|ip6|exists|redirect|exp|all)(?:(?::|=|/)?(?:\S*))?) ?)`)
	return spfMechanismPattern.FindAllString(spfString, -1)
}

func ExtractVersion(spfString string) string {
	spfVersionPattern := regexp.MustCompile("^v=(spf.)")
	spfVersion := spfVersionPattern.FindString(spfString)
	return spfVersion
}

func ExtractAllMechanism(mechanisms []string) string {
	allMachanism := ""
	for _, m := range mechanisms {
		if m == regexp.MustCompile(".*all.*").FindString(m) {
			allMachanism = m
		}
	}
	return allMachanism
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

func (spf *SpfRecord) String() string {
	return spf.Record
}

func (spf *SpfRecord) GetRedirectDomain() string {
	if len(spf.Mechanisms) > 0 {
		for _, m := range spf.Mechanisms {
			if m == regexp.MustCompile("redirect=(.*)").FindString(m) {
				return m
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

// func (spf *SpfRecord) IsRedirectMechanismStrong2(dnsResolver string) bool {
// 	if strings.TrimSpace(dnsResolver) == "" {
// 		dnsResolver = dnsresolver.CloudflareDNS
// 	}
// 	// Look at this
// 	redirectDomain := spf.GetRedirectDomain()
// 	if redirectDomain != nil {
// 		redirectMechanism := FromDomain(Param{DnsResolver: dnsResolver, Domain: *redirectDomain})

// 		if redirectMechanism != nil {
// 			return redirectMechanism.IsRecordStrong()
// 		} else {
// 			return false
// 		}
// 	} else {
// 		return false
// 	}

// }

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
	includeRecords, err := spf.GetIncludeRecords()
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

// need to check this. includes empty for "yourwebservers.com"
func (spf *SpfRecord) GetIncludeRecords() (map[string]*SpfRecord, error) {
	start := make(map[string]*SpfRecord)

	if spf.RecursionDepth >= 10 {
		return start, nil
	} else {
		includeDomains := spf.GetIncludeDomains()
		for _, domain := range includeDomains {
			// TODO: Fix DNS Resolver
			var err error
			start[domain], err = FromDomain(&shared.Options{Domain: domain})
			if err != nil {
				return nil, fmt.Errorf("error fetching include record spf %s", err)
			}
			start[domain].RecursionDepth = spf.RecursionDepth
		}
	}
	return start, nil
}
