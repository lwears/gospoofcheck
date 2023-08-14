package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strconv"

	"github.com/fatih/color"

	"github.com/lwears/gospoofcheck/pkg/dnsresolver"
	dmarcLib "github.com/lwears/gospoofcheck/pkg/emailprotections/dmarc"
	"github.com/lwears/gospoofcheck/pkg/emailprotections/shared"
	spfLib "github.com/lwears/gospoofcheck/pkg/emailprotections/spf"
)

var (
	red    = color.New(color.Bold, color.FgRed).SprintFunc()
	green  = color.New(color.Bold, color.FgGreen).SprintFunc()
	white  = color.New(color.Bold, color.FgWhite).SprintFunc()
	blue   = color.New(color.Bold, color.FgBlue).SprintFunc()
	yellow = color.New(color.Bold, color.FgYellow).SprintFunc()
)

type Color int

const (
	Red Color = iota
	Green
	Blue
	White
	Yellow
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
	case Yellow:
		fmt.Printf("\n%s %s", yellow("[+]"), text)
	}
}

func main() {
	opts, err := ReadOptions()
	if err != nil {
		// try to recover first, if you can’t then fatal)
		log.Fatal(err)
	}

	FormatOutput(White, fmt.Sprintf("Processing domain:\t\t\t%s", white(opts.Domain)))

	IsSpfStrong(opts)
	fmt.Println()

	spoofable := IsDmarcStrong(opts)

	if !spoofable {
		FormatOutput(Red, fmt.Sprintf("Spoofing possible for:\t\t%s!", white(opts.Domain)))
	} else {
		FormatOutput(Green, fmt.Sprintf("Spoofing not possible for:\t\t%s", white(opts.Domain)))
	}
	fmt.Println()
}

func ReadOptions() (*shared.Options, error) {
	cfg := &shared.Options{}
	flag.StringVar(&cfg.DnsResolver, "dnsresolver", dnsresolver.OpenDNS, "Use a specific dns resolver with port such as `8.8.8.8:53` or `1.1.1.1:53`")
	flag.Parse()

	cfg.Domain = flag.Arg(0)

	if cfg.Domain == "" {
		color.New(color.Bold, color.FgRed).Println("no domain passed")
		os.Exit(0)
	}

	return cfg, nil
}

func IsSpfStrong(opts *shared.Options) (bool, error) {
	spf, err := spfLib.FromDomain(opts)
	if err != nil {
		log.Fatal(err)
	}

	if spf.Record == "" {
		FormatOutput(Red, fmt.Sprintf("%s has no SPF record", white(opts.Domain)))
		return false, nil
	}

	FormatOutput(Blue, fmt.Sprintf("Found SPF record:\t\t\t%s", white(spf.Record)))

	strong, err := CheckSpfAllMechanism(spf, opts)
	if err != nil {
		return false, fmt.Errorf("error checking include mechanisms %s", err)
	}

	if !strong {

		redirectStrength, err := CheckSpfRedirectMechanisms(spf, opts.DnsResolver)
		if err != nil {
			log.Fatal(err)
		}

		includeStrength, err := CheckSpfIncludeMechanisms(spf, opts.DnsResolver)
		if err != nil {
			log.Fatal(err)
		}

		return redirectStrength || includeStrength, nil
	}

	return strong, nil
}

func CheckSpfRedirectMechanisms(spf *spfLib.SpfRecord, dnsResolver string) (bool, error) {
	redirectDomain := spf.GetRedirectDomain()
	if redirectDomain == "" {
		return false, nil
	}
	FormatOutput(Yellow, fmt.Sprintf("Processing an SPF redirect domain: %s", redirectDomain))
	return IsSpfStrong(&shared.Options{Domain: redirectDomain, DnsResolver: dnsResolver})
}

func CheckSpfIncludeMechanisms(spf *spfLib.SpfRecord, dnsResolver string) (bool, error) {
	includeDomainList := spf.GetIncludeDomains()

	for _, domain := range includeDomainList {
		FormatOutput(Yellow, fmt.Sprintf("Processing an SPF include domain: %s\n", domain))

		strong, err := IsSpfStrong(&shared.Options{Domain: domain, DnsResolver: dnsResolver})
		if err != nil {
			return false, fmt.Errorf("error checking if include domain has strong spf: %s", err)
		}

		if strong {
			return strong, nil
		}

	}
	return false, nil
}

func CheckSpfAllMechanism(spf *spfLib.SpfRecord, opts *shared.Options) (bool, error) {
	if spf.AllString == "" {
		FormatOutput(Red, "SPF record has no \"All\" string")
	}

	strong := slices.Contains([]string{"~all", "-all"}, spf.AllString)

	if strong {
		FormatOutput(Green, fmt.Sprintf("SPF includes an \"All\" item: \t %s", white(spf.AllString)))
		return strong, nil
	} else {
		FormatOutput(Red, fmt.Sprintf("SPF record \"All\" item is too weak: %s", white(spf.AllString)))
		return CheckSpfIncludeRedirect(spf, opts)
	}
}

func AreSpfIncludeMechanismsStrong(spf *spfLib.SpfRecord, opts *shared.Options) (bool, error) {
	FormatOutput(White, "Checking SPF include mechanisms")

	strong, err := spf.AreIncludeMechanismsStrong(opts)
	if err != nil {
		return false, fmt.Errorf("error checking include mechanisms %s", err)
	}

	if strong {
		FormatOutput(Green, "Include mechanisms include a strong record")
	} else {
		FormatOutput(Red, "Include mechanisms are not strong")
	}

	return strong, nil
}

func CheckSpfIncludeRedirect(spf *spfLib.SpfRecord, opts *shared.Options) (bool, error) {
	var err error
	strong := false

	if spf.GetRedirectDomain() != "" {
		strong, err = IsSpfRedirectStrong(spf, opts)
		if err != nil {
			return false, fmt.Errorf("error checking if redirect mechanism is strong %s", err)
		}
	}

	if !strong {
		strong, err = AreSpfIncludeMechanismsStrong(spf, opts)
		if err != nil {
			return false, err
		}
	}
	return strong, nil
}

func IsSpfRedirectStrong(spf *spfLib.SpfRecord, opts *shared.Options) (bool, error) {
	domain := spf.GetRedirectDomain()

	FormatOutput(White, fmt.Sprintf("Checking SPF redirect domain: %s", domain))

	redirectStrong, err := spf.IsRedirectMechanismStrong(opts.DnsResolver)
	if err != nil {
		return false, fmt.Errorf("error checking if redirect mechanism is strong %s", err)
	}

	if redirectStrong {
		FormatOutput(Green, "Redirect mechanism is strong.")
	} else {
		FormatOutput(Red, "Redirect mechanism is not strong.")
	}

	return redirectStrong, nil
}

func CheckDmarcPolicy(dmarc *dmarcLib.DmarcRecord) bool {
	if dmarc.Policy == "" {
		FormatOutput(Red, fmt.Sprintf("DMARC record has no policy: %s", white(dmarc.Policy)))
		return false
	}

	if slices.Contains([]string{"quarantine", "reject"}, dmarc.Policy) {
		FormatOutput(Green, fmt.Sprintf("DMARC policy set to:\t\t%s", white(dmarc.Policy)))
		return true
	}

	FormatOutput(Red, fmt.Sprintf("DMARC policy set to:\t\t%s", white(dmarc.Policy)))
	return false
}

func CheckDmarcExtras(dmarc *dmarcLib.DmarcRecord) {
	if dmarc.Percent != nil && *dmarc.Percent != 100 {
		FormatOutput(White, fmt.Sprintf("DMARC percentage is set to %s%% - spoofing might be possible", white(strconv.Itoa(*dmarc.Percent))))
	}
	if dmarc.RUA != "" {
		FormatOutput(White, fmt.Sprintf("Aggregate reports are sent to: \t%s", white(dmarc.RUA)))
	}
	if dmarc.RUF != "" {
		FormatOutput(White, fmt.Sprintf("Forensics reports are sent to: \t%s", white(dmarc.RUF)))
	}
}

// func CheckDmarcOrgPolicy() {}
// Seems like the old spoofcheck does a load of extra checks. will see if i can do them recursively

func IsDmarcStrong(opts *shared.Options) bool {
	dmarcRecordStrong := false

	dmarc, err := dmarcLib.FromDomain(opts)
	if err != nil {
		log.Fatal(err)
	}

	if dmarc.Record != "" {
		FormatOutput(Blue, fmt.Sprintf("Found DMARC record:\t\t\t%s", white(dmarc.Record)))
		CheckDmarcExtras(dmarc)
		dmarcRecordStrong = CheckDmarcPolicy(dmarc)
		// is this acceptable???
	} else if orgDomain, err := dmarc.GetOrgDomain(); orgDomain != dmarc.Domain && err == nil {
		FormatOutput(White, "No DMARC record found. Looking for organizational record")
		dmarcRecordStrong = IsDmarcStrong(&shared.Options{Domain: orgDomain, DnsResolver: opts.DnsResolver})
		// return CheckDmarcOrgPolicy()
		// dmarcRecordStrong = CheckDmarcOrgPolicy()
		// dmarcRecordStrong = false
	} else {
		FormatOutput(Red, fmt.Sprintf("%s has no DMARC record", white(opts.Domain)))
		dmarcRecordStrong = false
	}

	return dmarcRecordStrong
}
