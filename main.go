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
	flag "github.com/spf13/pflag"
)

var (
	regSplit  = regexp.MustCompile(`(?m)^}$\n*`)
	regX      = regexp.MustCompile(`{{\s*X\s*}}`)
	regProbes = map[string]*regexp.Regexp{
		"k":  regexp.MustCompile(`k:{{\s*(?P<id>\S+)\s*}}`),
		"kr": regexp.MustCompile(`kr:{{\s*(?P<id>\S+)\s*}}`),
	}
)

func main() {
	var targets *string = flag.StringP("targets", "t", "", "e.g. has_param=sk_buff")
	var dryRun *bool = flag.BoolP("dry-run", "n", false, "Dry run")
	flag.Parse()

	script := flag.Arg(0)
	if script == "" {
		log.Fatalf("No script provided")
	}

	targetMap := map[string]target.Target{}
	for _, t := range strings.Split(*targets, ",") {
		targetObj, err := target.New(t)
		if err != nil {
			log.Fatalf("Failed to create target object for %s: %+v\n", t, err)
		}
		targetMap[targetObj.ID()] = targetObj
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
	for _, template := range regSplit.Split(string(content), -1) {
		template += "}\n\n"

		for kind, regProbe := range regProbes {
			if !regProbe.MatchString(template) {
				continue
			}
			if regProbe.MatchString(template) {
				id := regProbe.FindStringSubmatch(template)[1]
				target, ok := targetMap[id]
				if !ok {
					log.Fatalf("Target %s not found: %s\n", id)
				}
				blocks, err := target.Blocks()
				if err != nil {
					log.Fatalf("Failed to get blocks for target %s: %+v\n", id, err)
				}
				for _, block := range blocks {
					outcome := regProbe.ReplaceAllString(template, block.Probe(kind))
					outcome = regX.ReplaceAllString(outcome, block.X())
					fmt.Fprintf(output, "%s", outcome)
				}
				continue
			}
		}
	}

	if !*dryRun {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
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
