package target

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type TargetFromFile struct {
	filename string
}

func newTargetFromFile(filename string) *TargetFromFile {
	return &TargetFromFile{filename: filename}
}

func (t *TargetFromFile) ID() string {
	return fmt.Sprintf("from_file:%s", t.filename)
}

func (t *TargetFromFile) Validate() (err error) {
	_, err = os.Stat(t.filename)
	return err
}

func (t *TargetFromFile) Blocks() (blocks []Block, err error) {
	file, err := os.Open(t.filename)
	if err != nil {
		return
	}
	defer file.Close()
	symbols := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		symbols = append(symbols, strings.TrimSpace(line))
	}
	if err = scanner.Err(); err != nil {
		return
	}
	return append(blocks, &BlockFromFile{symbols: symbols, target: t}), nil
}

type BlockFromFile struct {
	symbols []string
	target  *TargetFromFile
}

func (b *BlockFromFile) ID() string {
	return fmt.Sprintf("from_file:%s", b.target.filename)
}

func (b *BlockFromFile) VarReplaceFunc() func(string) string {
	return func(s string) string {
		return s
	}
}

func (b *BlockFromFile) ProbeTargets() []string {
	return b.symbols
}
