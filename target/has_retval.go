package target

import (
	"fmt"
	"strings"
)

type TargetHasRetval struct {
	param    string
	paramMap bool
}

func newTargetHasRetval(param string, paramMap bool) *TargetHasRetval {
	return &TargetHasRetval{
		param:    param,
		paramMap: paramMap,
	}
}

func (t *TargetHasRetval) ID() string {
	return fmt.Sprintf("has_retval:%s", t.param)
}

func (t *TargetHasRetval) Validate() error {
	if strings.Contains(t.param, " ") {
		return fmt.Errorf("invalid param: %s", t.param)
	}
	return nil
}

func (t *TargetHasRetval) Blocks() (blocks []Block, err error) {
	symbols, err := searchSymbolsByRetval(t.param)
	if err != nil {
		return
	}
	if len(symbols) == 0 {
		return nil, fmt.Errorf("no symbols found for param: %s", t.param)
	}
	return append(blocks, &BlockHasRetval{
		symbols: symbols,
		target:  t,
	}), nil
}

type BlockHasRetval struct {
	symbols []string
	target  *TargetHasRetval
}

func (b *BlockHasRetval) ID() string {
	return fmt.Sprintf("has_retval:%s", b.target.param)
}

func (b *BlockHasRetval) VarReplaceFunc() func(string) string {
	return func(s string) string {
		return s
	}
}

func (b *BlockHasRetval) ProbeTargets() []string {
	return b.symbols
}

func (b *BlockHasRetval) Begins() []string {
	if !b.target.paramMap {
		return nil
	}
	return begins(b.symbols)
}
