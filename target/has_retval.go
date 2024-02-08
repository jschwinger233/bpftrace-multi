package target

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
)

type TargetHasRetval struct {
	param string
}

func newTargetHasRetval(param string) *TargetHasRetval {
	return &TargetHasRetval{param: param}
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

func searchSymbolsByRetval(paramType string) (symbols []string, err error) {
	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel BTF: %+v\n", err)
	}

	iter := btfSpec.Iterate()
	for iter.Next() {
		typ := iter.Type
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}

		fnName := string(fn.Name)

		fnProto := fn.Type.(*btf.FuncProto)
		if ptr, ok := fnProto.Return.(*btf.Pointer); ok {
			if strct, ok := ptr.Target.(*btf.Struct); ok {
				if strct.Name == paramType {
					name := fnName
					symbols = append(symbols, name)
					continue
				}
			}
		}
	}
	return
}
