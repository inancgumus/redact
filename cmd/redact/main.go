// Command redact reads text from positional args or stdin and writes a
// copy with detected secrets replaced by a placeholder.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

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
		_, _ = fmt.Fprintln(stderr, "usage: redact [flags] [text...]")
		_, _ = fmt.Fprintln(stderr, "reads text from args; if none, reads from stdin.")
		fs.PrintDefaults()
	}

	opts := redact.DefaultOptions
	fs.Var((*runeFlag)(&opts.Mask), "mask",
		"character repeated for each byte of a secret")
	fs.Float64Var(&opts.MinEntropy, "min-entropy", opts.MinEntropy,
		"how random a value must look to be redacted (lower = redacts more)")
	fs.IntVar(&opts.MinSubmatch, "min-submatch", opts.MinSubmatch,
		"how strong a match must be to redact unknown secrets (higher = redacts less)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if rest := fs.Args(); len(rest) > 0 {
		_, err := io.WriteString(stdout, redact.String(strings.Join(rest, " "), opts))
		return err
	}

	// Peek so empty stdin prints usage instead of silently exiting.
	// The peeked byte stays buffered for ReadAll.
	br := bufio.NewReader(stdin)
	if _, err := br.Peek(1); err != nil {
		fs.Usage()
		return nil
	}

	buf, err := io.ReadAll(br)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	_, err = io.WriteString(stdout, redact.String(string(buf), opts))
	return err
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
