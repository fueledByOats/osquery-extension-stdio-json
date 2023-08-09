package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/creack/pty"
	"golang.org/x/term"
)

const (
	ExitString = "exit"
)

type Query struct {
	SQL string `json:"query"`
}

type Result struct {
	Data json.RawMessage `json:"data"`
}

func main() {
	err := runCommands()
	if err != nil {
		fmt.Println("Error:", err)
	}
}

func runCommands() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// needed to create socket
	cmd1 := exec.Command("osqueryi", "--nodisable_extensions")
	ptmx1, err := startCommandWithPty(cmd1)
	if err != nil {
		return err
	}
	defer ptmx1.Close()

	// Create the command. Replace `other_script.go` with your Go script.
	cmd2 := exec.Command("go", "run", "/home/sven/go/src/osquery-extension-stdio/server/extension.go", "--socket", "/home/sven/.osquery/shell.em")
	ptmx2, err := startCommandWithPty(cmd2)
	if err != nil {
		return err
	}
	defer ptmx2.Close()

	// Set stdin in raw mode.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Send multiple queries.
	err = sendQuery(ptmx2, "select * from users limit 2")
	if err != nil {
		return err
	}

	err = sendQuery(ptmx2, "select * from processes limit 3")
	if err != nil {
		return err
	}

	err = sendQuery(ptmx2, ExitString)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		os.Stdin.Close()
	}()

	buf := new(bytes.Buffer)
	multi := io.MultiWriter(os.Stdout, buf)

	go func() { _, _ = io.Copy(ptmx2, os.Stdin) }()
	_, _ = io.Copy(multi, ptmx2)

	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "{\"data\"") {
			continue
		}

		// do something with the result
		result := parseOsqueryResult(bytes.NewBufferString(line))
		fmt.Println(string(result.Data))
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error scanning buffer:", err)
	}

	return nil
}

func parseOsqueryResult(r io.Reader) *Result {
	decoder := json.NewDecoder(r)
	result := &Result{}
	if err := decoder.Decode(result); err != nil {
		fmt.Println("Error decoding osquery result:", err)
		return nil
	}

	return result
}

func startCommandWithPty(cmd *exec.Cmd) (*os.File, error) {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}

	return ptmx, nil
}

func sendQuery(w io.Writer, sql string) error {
	query := &Query{SQL: sql}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(query); err != nil {
		return err
	}

	_, err := w.Write([]byte("\n"))
	return err
}
