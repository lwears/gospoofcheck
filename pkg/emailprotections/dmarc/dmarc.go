package dmarc

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/lwears/gospoofcheck/pkg/emailprotections/shared"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
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

func (dmarc *DmarcRecord) String() string {
	return dmarc.Record
}

func FromDmarcString(dmarcString *string, domain *string) (*DmarcRecord, error) {

	if dmarcString == nil {
		return nil, errors.New("no dmarc string")
	}

	dmarc, err := InitalizeDmarc(dmarcString, domain)
	if err != nil {
		return nil, err
	}

	return dmarc, nil

}

/*
	marshaled, err := json.MarshalIndent(mappedTags, "", "   ")
	if err != nil {
		log.Fatalf("marshaling error: %s", err)
	}
	fmt.Println(string(marshaled))

*/

func InitalizeDmarc(dmarcString *string, domain *string) (*DmarcRecord, error) {

	tags := ExtractTags(*dmarcString)
	mappedTags := make(map[string]string)
	for i := 0; i < len(tags); i++ {
		mappedTags[tags[i][1]] = tags[i][2]
	}

	// marshaled, err := json.MarshalIndent(mappedTags, "", "   ")
	// if err != nil {
	// 	log.Fatalf("marshaling error: %s", err)
	// }
	// fmt.Println(string(marshaled))

	// version := mappedTags["v"]
	// policy := mappedTags["p"]
	// reportInterval := mappedTags["ri"]
	// ruf := mappedTags["ruf"]
	// rua := mappedTags["rua"]
	// subdomainPolicy := mappedTags["sp"]
	// spfAlignment := mappedTags["aspf"]
	// dkimAlignment := mappedTags["adkim"]

	dmarc := &DmarcRecord{
		Domain:          *domain,
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

	// marshaled2, err := json.MarshalIndent(dmarc, "", "   ")
	// if err != nil {
	// 	log.Fatalf("marshaling error: %s", err)
	// }
	// fmt.Println(string(marshaled2))

	return dmarc, nil
}

func ExtractTags(dmarcRecord string) [][]string {
	dmarcPattern := regexp.MustCompile(`(\w+)=(.*?)(?:; ?|$)`)
	return dmarcPattern.FindAllStringSubmatch(dmarcRecord, -1)
}

func FromDomain(opts *shared.Options) (*DmarcRecord, error) {
	dmarcString, err := GetDmarcStringForDomain(opts)

	if err != nil {
		log.Fatal(err)
	}

	dmarc, err := FromDmarcString(dmarcString, &opts.Domain)

	if err != nil {
		log.Fatal(err)
	}

	return dmarc, nil
}

func FindRecordFromAnswers(txtRecords []dns.RR) *string {
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

	result := FindRecordFromAnswers(r.Answer)

	return result, nil
}

func (dmarc *DmarcRecord) GetOrgRecord(dnsResolver string) (*DmarcRecord, error) {
	orgDomain := dmarc.Domain
	if orgDomain == dmarc.Domain {
		return nil, errors.New("org domain same as dmarc domain")
	}

	return FromDomain(&shared.Options{Domain: orgDomain, DnsResolver: dnsResolver})
}

func (dmarc *DmarcRecord) GetOrgDomain() string {
	url, err := url.Parse(dmarc.Domain)
	if err != nil {
		log.Fatal(err)
	}
	parts := strings.Split(url.Hostname(), ".")
	domain := parts[len(parts)-2] + "." + parts[len(parts)-1]
	return domain
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

func (dmarc *DmarcRecord) IsRecordStrong(dnsResolver string) (bool, error) {
	if dmarc.Policy != "" && slices.Contains([]string{"quarantine", "reject"}, dmarc.Policy) {
		return true, nil
	}
	return dmarc.IsOrgDomainStrong(dnsResolver)

}
