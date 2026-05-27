// Command redact reads text from -string or stdin and writes a copy with
// detected secrets replaced by a mask character.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/inancgumus/redact"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "redact:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("redact", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: redact [flags]")
		_, _ = fmt.Fprintln(stderr, "reads -string if set, otherwise stdin.")
		fs.PrintDefaults()
	}

	opts := redact.DefaultOptions
	fs.Var((*runeFlag)(&opts.Mask), "mask",
		"character repeated for each byte of a secret")
	fs.Float64Var(&opts.Entropy, "entropy", opts.Entropy,
		"how random a value must look to be redacted (lower = redacts more)")
	fs.IntVar(&opts.Strength, "strength", opts.Strength,
		"how strong a match must be to redact unknown secrets (higher = redacts less)")
	detect := fs.Bool("detect", false,
		"exit 1 if input contains secrets, 0 otherwise; no output")
	var input string
	fs.StringVar(&input, "string", "", "redact this text instead of reading stdin")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional args; use -string for inline text")
	}

	text := input
	if !isStringFlagSet(fs) {
		buf, err := io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		text = string(buf)
	}

	if *detect {
		if redact.HasSecrets(text, opts) {
			os.Exit(1)
		}
		return nil
	}

	_, err := io.WriteString(stdout, redact.String(text, opts))
	return err
}

func isStringFlagSet(fs *flag.FlagSet) bool {
	var set bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "string" {
			set = true
		}
	})
	return set
}

// runeFlag adapts a *rune to the flag.Value interface so the mask flag
// accepts exactly one character.
type runeFlag rune

func (r *runeFlag) String() string {
	if r == nil || *r == 0 {
		return ""
	}
	return string(*r)
}

func (r *runeFlag) Set(s string) error {
	runes := []rune(s)
	if len(runes) != 1 {
		return fmt.Errorf("mask must be one character, got %q", s)
	}
	*r = runeFlag(runes[0])
	return nil
}
