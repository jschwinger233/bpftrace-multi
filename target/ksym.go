package target

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
)

type Symbol struct {
	Type string
	Name string
	Addr uint64
}

var kallsyms map[string]*Symbol

func init() {
	kallsyms = make(map[string]*Symbol)
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		log.Fatalf("failed to open /proc/kallsyms: %v", err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}
		typ, name := parts[1], parts[2]
		kallsyms[name] = &Symbol{typ, name, addr}
	}
}
