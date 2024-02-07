package template

import (
	"fmt"
	"regexp"
	"strings"
)

var regProbe = regexp.MustCompile(`(k|kr):{{\s*(\S+)\s*}}`)

type Template struct {
	raw         string
	probeKind   string
	probeTarget string

	renderProbe   string
	renderVarFunc func(string) string
}

func New(raw string) (*Template, error) {
	if !regProbe.MatchString(raw) {
		return nil, fmt.Errorf("invalid template")
	}
	submatches := regProbe.FindStringSubmatch(raw)
	return &Template{
		raw:         raw,
		probeKind:   submatches[1],
		probeTarget: submatches[2],
	}, nil
}

func (t *Template) Raw() string {
	return t.raw
}

func (t *Template) ProbeTarget() string {
	return t.probeTarget
}

func (t *Template) SetProbeTargets(targets []string) {
	newProbes := []string{}
	for _, target := range targets {
		newProbes = append(newProbes, fmt.Sprintf("%s:%s", t.probeKind, target))
	}

	t.renderProbe = strings.Join(newProbes, ",")
}

func (t *Template) SetVars(replaceFunc func(string) string) {
	t.renderVarFunc = replaceFunc
}

func (t *Template) Render() string {
	return t.renderVarFunc(regProbe.ReplaceAllString(t.raw, t.renderProbe))
}
