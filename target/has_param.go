package target

import (
	"fmt"
	"regexp"
	"strings"
)

type TargetHasParam struct {
	param    string
	paramMap bool
}

func newTargetHasParam(param string, paramMap bool) Target {
	return &TargetHasParam{
		param:    param,
		paramMap: paramMap,
	}
}

func (t *TargetHasParam) ID() string {
	return fmt.Sprintf("has_param:%s", t.param)
}

func (t *TargetHasParam) Validate() error {
	if strings.Contains(t.param, " ") {
		return fmt.Errorf("invalid param: %s", t.param)
	}
	return nil
}

func (t *TargetHasParam) Blocks() (blocks []Block, err error) {
	pos2symbols, err := searchSymbolsByParam(t.param)
	if err != nil {
		return
	}
	if len(pos2symbols) == 0 {
		return nil, fmt.Errorf("no symbols found for param: %s", t.param)
	}
	for i := 0; i < 5; i++ {
		blocks = append(blocks, &BlockHasParam{
			paramPosition: i,
			symbols:       pos2symbols[i],
			target:        t,
		})
	}
	return
}

type BlockHasParam struct {
	paramPosition int
	symbols       []string

	target *TargetHasParam
}

func (b *BlockHasParam) ID() string {
	return fmt.Sprintf("has_param:%s:%d", b.target.param, b.paramPosition)
}

func (b *BlockHasParam) VarReplaceFunc() func(string) string {
	regex := regexp.MustCompile(fmt.Sprintf(`{{\s*%s\s*}}`, b.target.param))
	return func(template string) string {
		return regex.ReplaceAllString(template, fmt.Sprintf("arg%d", b.paramPosition))
	}
}

func (b *BlockHasParam) ProbeTargets() []string {
	return b.symbols
}

func (b *BlockHasParam) Begins() []string {
	if !b.target.paramMap {
		return nil
	}
	return begins(b.symbols)
}
