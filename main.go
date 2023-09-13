package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/fatih/color"

	dmarcLib "github.com/lwears/gospoofcheck/emailprotections/dmarc"
	"github.com/lwears/gospoofcheck/emailprotections/shared"
	spfLib "github.com/lwears/gospoofcheck/emailprotections/spf"
)

const (
	GooglePublicDNS = "8.8.8.8:53"
	CloudflareDNS   = "1.1.1.1:53"
	OpenDNS         = "208.67.222.222:53"
	Quad9           = "9.9.9.9:53"
)

type Spf struct {
	spfLib.SpfRecord
	IsStrong                 bool
	RedirectMechanismsStrong bool
	IncludeMechanismsStrong  bool
	IsRedirect               bool
	IsInclude                bool
}

type Dmarc struct {
	dmarcLib.DmarcRecord
	IsOrg bool
}

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
		log.Fatal(err)
	}

	FormatOutput(White, fmt.Sprintf("Processing domain:\t\t\t%s", white(opts.Domain)))

	spf, err := BuildSpfStats(opts, false, false)
	if err != nil {
		log.Fatal(err)
	}

	dmarc, err := GetDmarc(opts, false)
	if err != nil {
		log.Fatal(err)
	}

	spf.PrintStats(opts)
	dmarc.PrintStats(opts)
	spf.PrintIsSpoofable()
}

func (s *Spf) PrintIsSpoofable() {
	if !s.IsStrong {
		FormatOutput(Red, fmt.Sprintf("Spoofing possible for:\t\t%s!\n", white(s.Domain)))
	} else {
		FormatOutput(Green, fmt.Sprintf("Spoofing not possible for:\t\t%s\n", white(s.Domain)))
	}
}

func (s *Spf) PrintStats(opts *shared.Options) {
	if s.Record == "" {
		FormatOutput(Red, fmt.Sprintf("%s has no SPF record", white(s.Domain)))
		return
	} else {
		FormatOutput(Blue, fmt.Sprintf("Found SPF record:\t\t\t%s", white(s.Record)))
	}

	if s.AllString == "" {
		FormatOutput(Red, "SPF record has no \"All\" string")
	} else if s.IsAllMechanismStrong() {
		FormatOutput(Green, fmt.Sprintf("SPF includes an \"All\" item: \t %s", white(s.AllString)))
	} else {
		FormatOutput(Red, fmt.Sprintf("SPF record \"All\" item is too weak: %s", white(s.AllString)))
		redirectDomain := s.GetRedirectDomain()
		if redirectDomain == "" {
			FormatOutput(Yellow, fmt.Sprintf("Processing an SPF redirect domain: %s", redirectDomain))
		}
		redirectStrong, err := s.IsRedirectMechanismStrong(opts.DnsResolver)
		if err != nil {
			fmt.Printf("error checking if redirect mechanism is strong %s", err)
		}
		if redirectStrong {
			FormatOutput(Green, "Redirect mechanism is strong.")
		} else {
			FormatOutput(Red, "Redirect mechanism is not strong.")
			FormatOutput(White, "Checking SPF include mechanisms")
			includeMechanismsStrong, err := s.AreIncludeMechanismsStrong(opts)
			if err != nil {
				fmt.Printf("error checking include mechanisms %s", err)
			}

			if includeMechanismsStrong {
				FormatOutput(Green, "Include mechanisms include a strong record")
			} else {
				FormatOutput(Red, "Include mechanisms are not strong")
			}
		}

	}
}

func ReadOptions() (*shared.Options, error) {
	cfg := &shared.Options{}
	flag.StringVar(&cfg.DnsResolver, "dnsresolver", CloudflareDNS, "Use a specific dns resolver with port such as `8.8.8.8:53` or `1.1.1.1:53`")
	flag.Parse()

	cfg.Domain = flag.Arg(0)

	if cfg.Domain == "" {
		color.New(color.Bold, color.FgRed).Println("no domain passed")
		os.Exit(0)
	}

	return cfg, nil
}

func BuildSpfStats(opts *shared.Options, isRedirect, isInclude bool) (*Spf, error) {
	spf, err := spfLib.FromDomain(opts)
	if err != nil {
		log.Fatal(err)
	}

	if spf.Record == "" {
		return &Spf{SpfRecord: *spf, IsStrong: false}, nil
	}

	isRecordStrong, err := spf.IsRecordStrong(opts)
	if err != nil {
		return nil, err
	}

	s := Spf{SpfRecord: *spf, IsStrong: isRecordStrong}

	if spf.AllString != "" && spf.IsAllMechanismStrong() {
		if spf.GetRedirectDomain() != "" {
			redirectStrong, err := spf.IsRedirectMechanismStrong(opts.DnsResolver)
			if err != nil {
				return nil, fmt.Errorf("error checking if redirect mechanism is strong %s", err)
			}
			s.RedirectMechanismsStrong = redirectStrong

			if !redirectStrong {
				FormatOutput(White, "Checking SPF include mechanisms")
				includeMechanismsStrong, err := spf.AreIncludeMechanismsStrong(opts)
				if err != nil {
					return nil, fmt.Errorf("error checking include mechanisms %s", err)
				}
				s.IncludeMechanismsStrong = includeMechanismsStrong
			}
		}
	}

	return &s, nil
}

// func CheckSpfRedirectMechanisms(spf *spfLib.SpfRecord, dnsResolver string) (*Spf, error) {
// 	redirectDomain := spf.GetRedirectDomain()
// 	if redirectDomain == "" {
// 		return &Spf{}, nil
// 	}
// 	FormatOutput(Yellow, fmt.Sprintf("Processing an SPF redirect domain: %s", redirectDomain))
// 	return BuildSpfStats(&shared.Options{Domain: redirectDomain, DnsResolver: dnsResolver}, true, false)
// }

// func FirstStrongSpfFromIncludes(spf *spfLib.SpfRecord, dnsResolver string) (*Spf, error) {
// 	includeDomainList := spf.GetIncludeDomains()

// 	for _, domain := range includeDomainList {
// 		FormatOutput(Yellow, fmt.Sprintf("Processing an SPF include domain: %s\n", domain))

// 		includeSpfStats, err := BuildSpfStats(&shared.Options{Domain: domain, DnsResolver: dnsResolver}, false, true)
// 		if err != nil {
// 			return includeSpfStats, fmt.Errorf("error checking if include domain has strong spf: %s", err)
// 		}

// 		if includeSpfStats.IsStrong {
// 			return includeSpfStats, nil
// 		}

// 	}
// 	return &Spf{}, nil
// }

// func IsSpfRedirectStrong(spf *spfLib.SpfRecord, opts *shared.Options) (bool, error) {
// 	domain := spf.GetRedirectDomain()

// 	FormatOutput(White, fmt.Sprintf("Checking SPF redirect domain: %s", domain))

// 	redirectStrong, err := spf.IsRedirectMechanismStrong(opts.DnsResolver)
// 	if err != nil {
// 		return false, fmt.Errorf("error checking if redirect mechanism is strong %s", err)
// 	}

// 	return redirectStrong, nil
// }

// func CheckDmarcOrgPolicy() {}
// Seems like the old spoofcheck does a load of extra checks. will see if i can do them recursively

func GetDmarc(opts *shared.Options, isOrg bool) (*Dmarc, error) {
	dmarc, err := dmarcLib.FromDomain(opts)
	if err != nil {
		return nil, fmt.Errorf("error fetching dmarc %s", err)
	}

	if dmarc.Record != "" {
		return &Dmarc{DmarcRecord: *dmarc, IsOrg: isOrg}, nil
	}

	if orgDomain, err := dmarc.GetOrgDomain(); err == nil && orgDomain != dmarc.Domain {
		return GetDmarc(&shared.Options{Domain: orgDomain, DnsResolver: opts.DnsResolver}, true)
	}

	return &Dmarc{DmarcRecord: *dmarc}, nil
}

func (d *Dmarc) PrintStats(opts *shared.Options) {
	fmt.Println()
	if d.Record == "" {
		FormatOutput(Red, fmt.Sprintf("%s has no DMARC record\n", white(d.Domain)))
		return
	} else {
		FormatOutput(Blue, fmt.Sprintf("Found DMARC record:\t\t\t%s", white(d.Record)))
	}

	if d.Policy == "" {
		FormatOutput(Red, fmt.Sprintf("DMARC record has no policy: %s", white(d.Policy)))
	} else if d.IsPolicyStrong() {
		FormatOutput(Green, fmt.Sprintf("DMARC policy set to:\t\t%s", white(d.Policy)))
	} else {
		FormatOutput(Red, fmt.Sprintf("DMARC policy set to:\t\t%s", white(d.Policy)))
	}

	if d.Percent != nil && *d.Percent != 100 {
		FormatOutput(Yellow, fmt.Sprintf("DMARC percentage is set to:\t\t%s%% - %s", white(strconv.Itoa(*d.Percent)), yellow("spoofing might be possible")))
	}

	if d.IsOrg {
		FormatOutput(White, "No DMARC found but organizational record found")
	}

	if d.RUA != "" {
		FormatOutput(White, fmt.Sprintf("Aggregate reports are sent to:\t%s", white(d.RUA)))
	}
	if d.RUF != "" {
		FormatOutput(White, fmt.Sprintf("Forensics reports are sent to:\t%s", white(d.RUF)))
	}
}
