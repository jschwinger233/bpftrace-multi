package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"

	"github.com/jschwinger233/bpftrace-multi/target"
	"github.com/jschwinger233/bpftrace-multi/template"
	flag "github.com/spf13/pflag"
)

var regSplit = regexp.MustCompile(`(?m)^}$\n*`)

func main() {
	var dryRun *bool = flag.BoolP("dry-run", "n", false, "Dry run")
	flag.Parse()

	script := flag.Arg(0)
	if script == "" {
		log.Fatalf("No script provided")
	}

	var output io.Writer
	var err error
	if *dryRun {
		output = os.Stdout
	} else {
		if output, err = os.Create(script + ".bt"); err != nil {
			log.Fatalf("Failed to create temp file: %+v\n", err)
		}
	}

	content, err := os.ReadFile(script)
	if err != nil {
		log.Fatalf("Failed to read file %s: %+v\n", script, err)
	}
	for _, rawBlock := range regSplit.Split(string(content), -1) {
		rawBlock = strings.TrimSpace(rawBlock)
		if rawBlock == "" {
			continue
		}

		templateObj, err := template.New(rawBlock + "\n}\n\n")
		if err != nil {
			fmt.Fprintf(output, "%s", rawBlock)
			continue
		}

		targetObj, err := target.New(templateObj.ProbeTarget())
		if err != nil {
			log.Fatalf("Failed to create target object due to %+v", err)
		}
		blocks, err := targetObj.Blocks()
		if err != nil {
			log.Fatalf("Failed to get blocks for target %s: %+v\n", targetObj.ID(), err)
		}
		for _, block := range blocks {
			templateObj.SetProbeTargets(block.ProbeTargets())
			templateObj.SetVars(block.VarReplaceFunc())
			fmt.Fprintf(output, "%s", templateObj.Render())
		}

	}

	if !*dryRun {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		go func() {
			<-ctx.Done()
			fmt.Println("Interrupted, waiting for bpftrace to exit...")
		}()

		cmd := exec.CommandContext(ctx, "bpftrace", script+".bt")
		cmd.Env = os.Environ()
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Fatalf("Failed to get stdout pipe: %+v\n", err)
		}
		go io.Copy(os.Stdout, stdout)
		stderr, err := cmd.StderrPipe()
		if err != nil {
			log.Fatalf("Failed to get stderr pipe: %+v\n", err)
		}
		go io.Copy(os.Stderr, stderr)
		if err := cmd.Start(); err != nil {
			log.Fatalf("Failed to start bpftrace: %+v\n", err)
		}
		if err := cmd.Wait(); err != nil {
			log.Fatalf("Failed to exec bpftrace: %+v\n", err)
		}
	}
}