package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/fatih/color"
	"github.com/lwears/gospoofcheck/pkg/dnsresolver"
	spfLib "github.com/lwears/gospoofcheck/pkg/emailprotections"
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
		log.Fatal()
	}

	IsSpfStrong(opts)
}

func ReadOptions() (*spfLib.Options, error) {
	cfg := &spfLib.Options{}
	flag.StringVar(&cfg.DnsResolver, "dnsresolver", dnsresolver.CloudflareDNS, "Use a specific dns resolver with port such as `8.8.8.8:53` or `1.1.1.1:53`")
	flag.Parse()

	cfg.Domain = flag.Arg(0)

	if cfg.Domain == "" {
		log.Fatal("No Domain passed")
	}

	return cfg, nil
}

func IsSpfStrong(opts *spfLib.Options) bool {

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
	return IsSpfStrong(&spfLib.Options{Domain: *redirectDomain, DnsResolver: dnsResolver})
}

func CheckSpfIncludeMechanisms(spf *spfLib.SpfRecord, dnsResolver string) bool {
	includeDomainList := spf.GetIncludeDomains()
	for _, domain := range includeDomainList {
		FormatOutput(White, fmt.Sprintf("Processing an SPF include domain: %s\n\n", domain))
		if IsSpfStrong(&spfLib.Options{Domain: domain, DnsResolver: dnsResolver}) {
			return true
		}
	}
	return false
}

func CheckSpfAllMechanism(spf *spfLib.SpfRecord, opts *spfLib.Options) bool {
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

func AreSpfIncludeMechanismsStrong(spf *spfLib.SpfRecord, opts *spfLib.Options) bool {
	FormatOutput(White, "Checking SPF include mechanisms")
	strong := spf.AreIncludeMechanismsStrong(opts)
	if strong {
		FormatOutput(Green, "Include mechanisms include a strong record")
	} else {
		FormatOutput(Red, "Include mechanisms are not strong")
	}
	return strong
}

func CheckSpfIncludeRedirect(spf *spfLib.SpfRecord, opts *spfLib.Options) bool {
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
