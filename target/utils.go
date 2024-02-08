package target

import (
	"fmt"
	"strings"
)

func begins(symbols []string) (begins []string) {
	availableSymbols := []string{}
	for _, symbol := range symbols {
		if kallsyms[symbol] != nil {
			availableSymbols = append(availableSymbols, symbol)
		}
	}
	for symbol, params := range getParamMap(availableSymbols) {
		param := strings.Join(params, ",")
		if len(param) > 63 {
			param = param[:63]
		}
		begins = append(begins, fmt.Sprintf(`@param[kaddr("%s")] = "%s";`, symbol, param))
	}
	return
}
