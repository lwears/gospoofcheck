package main

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func main2() {

	domain := "google.com"  // Define domain
	nameserver := "8.8.8.8" // Define nameserver as per your requirement
	c := dns.Client{}
	m := dns.Msg{}

	m.SetQuestion(domain+".", dns.TypeTXT)
	l, _, err := c.Exchange(&m, nameserver+":53")

	if err != nil {
		fmt.Print(err.Error())
	}

	spf := []string{}
	for _, ans := range l.Answer {
		x := ans.(*dns.TXT)
		for _, t := range x.Txt {
			if strings.Contains(t, "v=spf1") {
				spf = append(spf, t)
			}
		}
	}

	fmt.Println(spf)
}
