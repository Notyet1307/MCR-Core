package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	mcr "github.com/Notyet1307/MCR-Core"
	"github.com/Notyet1307/MCR-Core/internal/jsonstrict"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return fail(stderr, "a command is required")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	workspacePath := flags.String("workspace", "", "workspace path")
	var factID, taskID, kind *string
	if command == "query" {
		factID = flags.String("fact-id", "", "exact Fact ID")
		taskID = flags.String("task-id", "", "exact Task ID")
		kind = flags.String("kind", "", "exact Fact Kind")
	}
	if command != "submit" && command != "query" && command != "replay" && command != "verify" {
		return fail(stderr, fmt.Sprintf("unknown command %q", command))
	}
	if err := flags.Parse(args[1:]); err != nil {
		return fail(stderr, err.Error())
	}
	if *workspacePath == "" {
		return fail(stderr, "--workspace is required")
	}
	if flags.NArg() != 0 {
		return fail(stderr, "unexpected positional arguments")
	}

	workspace, err := mcr.Open(*workspacePath)
	if err != nil {
		return fail(stderr, err.Error())
	}
	encoder := json.NewEncoder(stdout)
	switch command {
	case "submit":
		raw, err := io.ReadAll(stdin)
		if err != nil {
			return fail(stderr, err.Error())
		}
		if err := jsonstrict.Validate(raw); err != nil {
			return fail(stderr, err.Error())
		}
		var submission mcr.Submission
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&submission); err != nil {
			return fail(stderr, err.Error())
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			return fail(stderr, "stdin must contain exactly one JSON value")
		}
		fact, err := workspace.Submit(submission)
		if err != nil {
			return fail(stderr, err.Error())
		}
		if err := encoder.Encode(fact); err != nil {
			return fail(stderr, err.Error())
		}
	case "query":
		facts, err := workspace.Query(mcr.FactQuery{FactID: *factID, TaskID: *taskID, Kind: *kind})
		if err != nil {
			return fail(stderr, err.Error())
		}
		if err := encoder.Encode(facts); err != nil {
			return fail(stderr, err.Error())
		}
	case "replay":
		projection, err := workspace.Replay()
		if err != nil {
			return fail(stderr, err.Error())
		}
		if err := encoder.Encode(projection); err != nil {
			return fail(stderr, err.Error())
		}
	case "verify":
		verification, err := workspace.Verify()
		if err != nil {
			return fail(stderr, err.Error())
		}
		if err := encoder.Encode(verification); err != nil {
			return fail(stderr, err.Error())
		}
		if verification.Integrity != mcr.IntegritySealedValid {
			return 1
		}
	}
	return 0
}

func fail(stderr io.Writer, message string) int {
	_ = json.NewEncoder(stderr).Encode(map[string]string{"error": message})
	return 2
}
