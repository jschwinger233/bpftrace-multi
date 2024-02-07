package target

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/ebpf/btf"
)

type TargetHasParam struct {
	param string
}

func newTargetHasParam(param string) Target {
	return &TargetHasParam{
		param: param,
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

func searchSymbolsByParam(paramType string) (pos2symbols map[int][]string, err error) {
	pos2symbols = map[int][]string{}

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
		i := 0
		for _, p := range fnProto.Params {
			if ptr, ok := p.Type.(*btf.Pointer); ok {
				if strct, ok := ptr.Target.(*btf.Struct); ok {
					if strct.Name == paramType && i < 5 {
						name := fnName
						pos2symbols[i] = append(pos2symbols[i], name)
						continue
					}
				}
			}
			i++
		}
	}
	return
}
