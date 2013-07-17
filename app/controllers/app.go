package controllers

import (
	"github.com/robfig/revel"
	"github.com/samuelkadolph/spf-buddy/lib"
)

type App struct {
	*revel.Controller
}

func (c App) Index(domain string) revel.Result {
	var includesSpecifiedDomain bool
	var err error
	var spf *lib.SPF
	var suggested *lib.SPF

	specifiedDomain, found := revel.Config.String("domain")
	if !found {
		panic("domain must be set in app.conf")
	}

	if domain != "" {
		spf, err = lib.LookupSPF(domain)

		if spf != nil {
			includesSpecifiedDomain = spf.Includes(specifiedDomain)
			if !includesSpecifiedDomain {
				suggested = &lib.SPF{spf.Entries}
				suggested.InsertInclude(specifiedDomain)
			}
		}
	}

	return c.Render(domain, err, includesSpecifiedDomain, specifiedDomain, spf, suggested)
}
