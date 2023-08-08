package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"

	"github.com/fatih/color"
	"github.com/lwears/gospoofcheck/pkg/dnsresolver"
	dmarcLib "github.com/lwears/gospoofcheck/pkg/emailprotections/dmarc"
	"github.com/lwears/gospoofcheck/pkg/emailprotections/shared"
	spfLib "github.com/lwears/gospoofcheck/pkg/emailprotections/spf"
	"golang.org/x/exp/slices"
)

var red = color.New(color.Bold, color.FgRed).SprintFunc()
var green = color.New(color.Bold, color.FgGreen).SprintFunc()
var white = color.New(color.Bold, color.FgWhite).SprintFunc()
var blue = color.New(color.Bold, color.FgBlue).SprintFunc()

type Color int

const (
	Red Color = iota
	Green
	Blue
	White
)

func FormatOutput(color Color, text string) {
	switch color {
	case Red:
		fmt.Printf("\n%s %s", red("[+]"), text)
	case Green:
		fmt.Printf("\n%s %s", green("[+]"), text)
	case Blue:
		fmt.Printf("\n%s %s", blue("[+]"), text)
	case White:
		fmt.Printf("\n%s %s", white("[+]"), text)
	}
}

func main() {

	opts, err := ReadOptions()

	if err != nil {
		log.Fatal(err)
	}

	IsSpfStrong(opts)
	fmt.Println()
	IsDmarcStrong(opts)
	fmt.Println()
}

func ReadOptions() (*shared.Options, error) {
	cfg := &shared.Options{}
	flag.StringVar(&cfg.DnsResolver, "dnsresolver", dnsresolver.CloudflareDNS, "Use a specific dns resolver with port such as `8.8.8.8:53` or `1.1.1.1:53`")
	flag.Parse()

	cfg.Domain = flag.Arg(0)

	if cfg.Domain == "" {
		log.Fatal("no domain passed")
	}

	return cfg, nil
}

func IsSpfStrong(opts *shared.Options) bool {

	FormatOutput(White, fmt.Sprintf("Processing domain: %s", white(opts.Domain)))

	spf := spfLib.FromDomain(opts)

	if spf == nil {
		FormatOutput(Green, fmt.Sprintf("%s has no SPF record", white(opts.Domain)))
		return false
	}

	FormatOutput(White, fmt.Sprintf("Found SPF record: %s", spf.Record))

	strong := CheckSpfAllMechanism(spf, opts)

	if !strong {
		redirectStrength := CheckSpfRedirectMechanisms(spf, opts.DnsResolver)
		includeStrength := CheckSpfIncludeMechanisms(spf, opts.DnsResolver)
		strong = redirectStrength || includeStrength
	}

	return strong
}

func CheckSpfRedirectMechanisms(spf *spfLib.SpfRecord, dnsResolver string) bool {
	redirectDomain := spf.GetRedirectDomain()
	if redirectDomain == nil {
		return false
	}
	FormatOutput(White, fmt.Sprintf("Processing an SPF redirect domain: %s", *redirectDomain))
	return IsSpfStrong(&shared.Options{Domain: *redirectDomain, DnsResolver: dnsResolver})
}

func CheckSpfIncludeMechanisms(spf *spfLib.SpfRecord, dnsResolver string) bool {
	includeDomainList := spf.GetIncludeDomains()
	for _, domain := range includeDomainList {
		FormatOutput(White, fmt.Sprintf("Processing an SPF include domain: %s\n\n", domain))
		if IsSpfStrong(&shared.Options{Domain: domain, DnsResolver: dnsResolver}) {
			return true
		}
	}
	return false
}

func CheckSpfAllMechanism(spf *spfLib.SpfRecord, opts *shared.Options) bool {
	if spf.AllString == "" {
		FormatOutput(Red, "SPF record has no \"All\" string")
	}

	strong := slices.Contains([]string{"~all", "-all"}, spf.AllString)

	if strong {
		FormatOutput(Blue, fmt.Sprintf("SPF record contains an \"All\" item: %s", white(spf.AllString)))
	} else {
		FormatOutput(Red, fmt.Sprintf("SPF record \"All\" item is too weak: %s", white(spf.AllString)))
	}

	return strong || CheckSpfIncludeRedirect(spf, opts)

}

func AreSpfIncludeMechanismsStrong(spf *spfLib.SpfRecord, opts *shared.Options) bool {
	FormatOutput(White, "Checking SPF include mechanisms")
	strong := spf.AreIncludeMechanismsStrong(opts)
	if strong {
		FormatOutput(Green, "Include mechanisms include a strong record")
	} else {
		FormatOutput(Red, "Include mechanisms are not strong")
	}
	return strong
}

func CheckSpfIncludeRedirect(spf *spfLib.SpfRecord, opts *shared.Options) bool {
	return IsSpfRedirectStrong(spf) || AreSpfIncludeMechanismsStrong(spf, opts)
}

func IsSpfRedirectStrong(spf *spfLib.SpfRecord) bool {
	domain := spf.GetRedirectDomain()
	FormatOutput(White, fmt.Sprintf("Checking SPF redirect domain: %s", *domain))
	redirectStrong := spf.IsRedirectMechanismStrong(dnsresolver.CloudflareDNS)
	if redirectStrong {
		FormatOutput(Green, "Redirect mechanism is strong.")
	} else {
		FormatOutput(Red, "Redirect mechanism is not strong.")
	}
	return redirectStrong
}

func CheckDmarcPolicy(dmarc *dmarcLib.DmarcRecord) bool {
	if dmarc.Policy == "" {
		FormatOutput(Green, fmt.Sprintf("DMARC record has no policy: %s", white(dmarc.Policy)))
		return false
	}

	if slices.Contains([]string{"quarantine", "reject"}, dmarc.Policy) {
		FormatOutput(Green, fmt.Sprintf("DMARC policy set to: %s", white(dmarc.Policy)))
		return true
	}

	FormatOutput(Red, fmt.Sprintf("DMARC policy set to: %s", white(dmarc.Policy)))
	return false

}

func CheckDmarcExtras(dmarc *dmarcLib.DmarcRecord) {
	if dmarc.Percent != nil && *dmarc.Percent != 100 {
		FormatOutput(White, fmt.Sprintf("DMARC percentage is set to %s%% - spoofing might be possible", white(strconv.Itoa(*dmarc.Percent))))
	}
	if dmarc.RUA != "" {
		FormatOutput(White, fmt.Sprintf("Aggregate reports will be sent: %s", white(dmarc.RUA)))

	}
	if dmarc.RUF != "" {
		FormatOutput(White, fmt.Sprintf("Forensics reports will be sent: %s", white(dmarc.RUF)))

	}
}

// func CheckDmarcOrgPolicy() {}

func IsDmarcStrong(opts *shared.Options) bool {

	dmarcRecordStrong := false

	FormatOutput(White, fmt.Sprintf("Processing domain: %s", white(opts.Domain)))

	dmarc, err := dmarcLib.FromDomain(opts)

	if err != nil {
		log.Fatal(err)
	}

	if dmarc.Record != "" {
		CheckDmarcExtras(dmarc)
		dmarcRecordStrong = CheckDmarcPolicy(dmarc)
	} else if dmarc.GetOrgDomain() != dmarc.Domain {
		FormatOutput(White, "No DMARC record found. Looking for organizational record")
		// return CheckDmarcOrgPolicy()
		// dmarcRecordStrong = CheckDmarcOrgPolicy()
		dmarcRecordStrong = false
	} else {
		FormatOutput(Red, fmt.Sprintf("%s has no DMARC record", white(opts.Domain)))
		dmarcRecordStrong = false
	}

	return dmarcRecordStrong

}
