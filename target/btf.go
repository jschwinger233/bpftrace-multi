package target

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf/btf"
)

var btfSpecs []*btf.Spec

func initBtfSpecs(allKmods bool) (err error) {
	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("failed to load kernel BTF: %v", err)
	}
	btfSpecs = append(btfSpecs, btfSpec)

	if allKmods {
		files, err := os.ReadDir("/sys/kernel/btf")
		if err != nil {
			return fmt.Errorf("failed to read BTF: %v", err)
		}

		for _, file := range files {
			if file.IsDir() || file.Name() == "vmlinux" {
				continue
			}
			f, err := os.Open("/sys/kernel/btf/" + file.Name())
			if err != nil {
				return fmt.Errorf("failed to open BTF: %v", err)
			}
			defer f.Close()

			modSpec, err := btf.LoadSplitSpecFromReader(f, btfSpec)
			if err != nil {
				return fmt.Errorf("failed to load BTF: %v", err)
			}
			btfSpecs = append(btfSpecs, modSpec)
		}
	}
	return
}

func getParamMap(symbols []string) map[string][]string {
	symbolSet := map[string]struct{}{}
	for _, sym := range symbols {
		symbolSet[sym] = struct{}{}
	}

	paramMap := map[string][]string{}
	for _, spec := range btfSpecs {
		iter := spec.Iterate()
		for iter.Next() {
			typ := iter.Type
			fn, ok := typ.(*btf.Func)
			if !ok {
				continue
			}

			fnName := string(fn.Name)
			if _, ok := symbolSet[fnName]; !ok {
				continue
			}

			fnProto := fn.Type.(*btf.FuncProto)
			for _, param := range fnProto.Params {
				paramMap[fnName] = append(paramMap[fnName], string(param.Name))
			}
		}
	}

	return paramMap
}

func searchSymbolsByRetval(paramType string) (symbols []string, err error) {
	for _, spec := range btfSpecs {
		iter := spec.Iterate()
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
	}
	return
}

func searchSymbolsByParam(paramType string) (pos2symbols map[int][]string, err error) {
	pos2symbols = map[int][]string{}

	for _, spec := range btfSpecs {
		iter := spec.Iterate()
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
	}
	return
}
