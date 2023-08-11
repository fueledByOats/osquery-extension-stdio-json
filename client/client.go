package client

import (
	"bufio"
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

type Client struct {
	ptmx1     *os.File
	ptmx2     *os.File
	ctx       context.Context
	cancel    context.CancelFunc
	origState *term.State
}

func (c *Client) Start(command string) error {
	c.ctx, c.cancel = context.WithCancel(context.Background())

	// needed to create osquery socket
	cmd1 := exec.Command("osqueryi", "--nodisable_extensions")
	var err error
	c.ptmx1, err = startCommandWithPty(cmd1)
	if err != nil {
		return fmt.Errorf("failed to start cmd1: %v", err)
	}

	// Split the command string into command and arguments
	cmdArgs := strings.Split(command, " ")
	cmd2 := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	c.ptmx2, err = startCommandWithPty(cmd2)
	if err != nil {
		return fmt.Errorf("failed to start cmd2: %v", err)
	}

	// Set stdin in raw mode and store the original state.
	c.origState, err = term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to set stdin in raw mode: %v", err)
	}
	return nil
}

func (c *Client) SendQuery(sql string) (*Result, error) {
	query := &Query{SQL: sql}
	encoder := json.NewEncoder(c.ptmx2)
	if err := encoder.Encode(query); err != nil {
		return nil, err
	}

	_, err := c.ptmx2.Write([]byte("\n"))
	if err != nil {
		return nil, err
	}

	// Wait for the response
	var response string
	scanner := bufio.NewScanner(c.ptmx2)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "{\"data\"") {
			response = line
			break
		}
	}

	// If we've received the desired response, ignore the I/O error
	if response != "" {
		return parseOsqueryResult(strings.NewReader(response)), nil
	}

	if err := scanner.Err(); err != nil {
		// Check if the error is due to the osquery extension closing the connection
		if strings.Contains(err.Error(), "input/output error") {
			// Ignore the error and return nil
			return nil, nil
		}
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	return nil, fmt.Errorf("no valid response received")
}

func (c *Client) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	if c.ptmx1 != nil {
		c.ptmx1.Close()
	}
	if c.ptmx2 != nil {
		c.ptmx2.Close()
	}
	if c.origState != nil {
		term.Restore(int(os.Stdin.Fd()), c.origState)
	}
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
