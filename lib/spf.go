package lib

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const blankSPF = "v=spf1 ~all"

type SPF struct {
	Entries []string
}

var spfRegexp = regexp.MustCompile("\\Av=spf1")

func LookupSPF(domain string) (*SPF, error) {
	txt, err := net.LookupTXT(domain)

	if _, ok := err.(*net.DNSError); ok {
		_, err := net.LookupHost(domain)

		if err != nil {
			return nil, err
		} else {
			return ParseSPF(blankSPF)
		}
	} else if err != nil {
		return nil, err
	}

	for _, record := range txt {
		if spfRegexp.MatchString(record) {
			return ParseSPF(record)
		}
	}

	return ParseSPF(blankSPF)
}

func ParseSPF(txt string) (*SPF, error) {
	var b bytes.Buffer

	spf := new(SPF)

	for _, c := range txt {
		switch c {
		case ' ':
			spf.Entries = append(spf.Entries, b.String())
			b.Reset()
		default:
			b.WriteRune(c)
		}
	}

	spf.Entries = append(spf.Entries, b.String())
	b.Reset()

	return spf, nil
}

func (s *SPF) InsertInclude(domain string) {
	value := fmt.Sprintf("include:%s", domain)

	s.Entries = append(s.Entries[:1], append([]string{value}, s.Entries[1:]...)...)
}

func (s *SPF) Includes(domain string) bool {
	value := fmt.Sprintf("include:%s", domain)

	for _, entry := range s.Entries {
		if entry == value {
			return true
		}
	}

	return false
}

func (s *SPF) Value() string {
	return strings.Join(s.Entries, " ")
}
