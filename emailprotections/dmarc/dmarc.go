package dmarc

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/lwears/gospoofcheck/emailprotections/shared"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

type DmarcRecord struct {
	Domain          string
	Version         string
	Policy          string
	Percent         *int
	RUA             string
	RUF             string
	SubdomainPolicy string
	DkimAlignment   string
	SpfAlignment    string
	ReportInterval  string
	Record          string
}

func FromDmarcString(dmarcString *string, domain string) (*DmarcRecord, error) {
	dmarc, err := newDmarc(dmarcString, domain)
	if err != nil {
		return nil, err
	}

	return dmarc, nil
}

func FromDomain(opts *shared.Options) (*DmarcRecord, error) {
	dmarcString, err := GetDmarcStringForDomain(opts)
	if err != nil {
		return nil, errors.New("error getting dmarc string for domain")
	}

	dmarc, err := FromDmarcString(dmarcString, opts.Domain)
	if err != nil {
		return nil, fmt.Errorf("\nerror parsing dmarc string: %s", err)
	}

	return dmarc, nil
}

func GetDmarcStringForDomain(opts *shared.Options) (*string, error) {
	if !shared.IsValidDomainName(opts.Domain) {
		return nil, shared.InvalidDomainError
	}

	fqnd := dns.Fqdn(fmt.Sprintf("_dmarc.%s", opts.Domain))
	m := dns.Msg{}
	m.SetQuestion(fqnd, dns.TypeTXT)
	m.RecursionDesired = true
	// Whatever this is fixed it
	m.SetEdns0(4096, false)
	r, err := dns.Exchange(&m, opts.DnsResolver)
	if err != nil {
		return nil, err
	}

	result := findRecordFromAnswers(r.Answer)

	return result, nil
}

func (dmarc *DmarcRecord) GetOrgRecord(dnsResolver string) (*DmarcRecord, error) {
	orgDomain := dmarc.Domain
	if orgDomain == dmarc.Domain {
		return nil, errors.New("org domain same as dmarc domain")
	}

	return FromDomain(&shared.Options{Domain: orgDomain, DnsResolver: dnsResolver})
}

func (dmarc *DmarcRecord) GetOrgDomain() (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(dmarc.Domain)
}

func (dmarc *DmarcRecord) IsOrgDomainStrong(dnsResolver string) (bool, error) {
	orgRecord, err := dmarc.GetOrgRecord(dnsResolver)
	if err != nil {
		return false, err
	}

	if orgRecord.SubdomainPolicy != "" {
		return orgRecord.IsSubdomainPolicyStrong(), nil
	}

	return orgRecord.IsRecordStrong(dnsResolver)
}

func (dmarc *DmarcRecord) IsSubdomainPolicyStrong() bool {
	return slices.Contains([]string{"quarantine", "reject"}, dmarc.SubdomainPolicy)
}

func (dmarc *DmarcRecord) IsPolicyStrong() bool {
	return slices.Contains([]string{"quarantine", "reject"}, dmarc.Policy)
}

func (dmarc *DmarcRecord) IsRecordStrong(dnsResolver string) (bool, error) {
	if dmarc.Policy != "" && slices.Contains([]string{"quarantine", "reject"}, dmarc.Policy) {
		return true, nil
	}
	return dmarc.IsOrgDomainStrong(dnsResolver)
}

func newDmarc(dmarcString *string, domain string) (*DmarcRecord, error) {
	if dmarcString == nil {
		return &DmarcRecord{Domain: domain}, nil
	}

	tags := extractTags(*dmarcString)
	mappedTags := make(map[string]string)
	for i := 0; i < len(tags); i++ {
		mappedTags[tags[i][1]] = tags[i][2]
	}

	dmarc := &DmarcRecord{
		Domain:          domain,
		Record:          *dmarcString,
		Version:         mappedTags["v"],
		Policy:          mappedTags["p"],
		ReportInterval:  mappedTags["ri"],
		RUF:             mappedTags["ruf"],
		RUA:             mappedTags["rua"],
		SubdomainPolicy: mappedTags["sp"],
		SpfAlignment:    mappedTags["aspf"],
		DkimAlignment:   mappedTags["padkim"],
	}

	if _, ok := mappedTags["pct"]; ok {
		percent, err := strconv.Atoi(mappedTags["pct"])
		if err != nil {
			return nil, fmt.Errorf("error converting percent to integer type %w", err)
		}
		dmarc.Percent = &percent
	}

	return dmarc, nil
}

func extractTags(dmarcRecord string) [][]string {
	dmarcPattern := regexp.MustCompile(`(\w+)=\s*([^;]*?)(?:; ?|$)`)
	return dmarcPattern.FindAllStringSubmatch(dmarcRecord, -1)
}

func findRecordFromAnswers(txtRecords []dns.RR) *string {
	for _, a := range txtRecords {
		x := a.(*dns.TXT)
		for _, t := range x.Txt {
			if strings.Contains(t, "v=DMARC") {
				return &t
			}
		}
	}
	return nil
}
