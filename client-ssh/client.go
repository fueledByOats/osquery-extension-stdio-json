package main

import (
	"bufio"
	"fmt"
	"io"
	"log"

	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

func main() {
	// Configuration
	user := "sven"
	server := "localhost:22"
	privateKeyFile := "/home/sven/.ssh/id_ed25519"
	command := "cd /home/sven/go/src/osquery-extension-stdio/server && go run extension.go --socket /home/sven/.osquery/shell.em"
	queries := []string{
		"{\"query\":\"select * from users limit 2\"}\n",
		"{\"query\":\"select * from processes limit 3\"}\n",
		"{\"query\":\"select * from users limit 1\"}\n",
		"{\"query\":\"select * from users limit 1\"}\n",
		"{\"query\":\"select * from users limit 1\"}\n",
	}

	// Establish SSH connection and start session
	session, stdin, stdout, err := startSession(user, server, privateKeyFile, command)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	// Create a channel to signal when a response has been fully read
	responseRead := make(chan bool)

	// Start a goroutine to read from stdout
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
			// Signal that the response has been fully read
			responseRead <- true
		}
		if err := scanner.Err(); err != nil {
			log.Fatal("Failed to read from stdout: ", err)
		}
	}()

	// Send queries and wait for results
	for _, query := range queries {
		if err := sendQuery(stdin, stdout, query, responseRead); err != nil {
			log.Fatal(err)
		}
	}

	// Wait for the command to finish
	if err := session.Wait(); err != nil {
		log.Fatal("Failed to wait for command: ", err)
	}
}

func startSession(user, server, privateKeyFile, command string) (*ssh.Session, io.WriteCloser, io.Reader, error) {
	// Read the private key file
	privateKeyBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load private key: %w", err)
	}

	// Parse the private key
	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(privateKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // this is unsafe
	}

	client, err := ssh.Dial("tcp", server, config)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to dial: %w", err)
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create session: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	if err := session.Start(command); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to start command: %w", err)
	}

	return session, stdin, stdout, nil
}

func sendQuery(stdin io.WriteCloser, stdout io.Reader, query string, responseRead chan bool) error {
	_, err := io.WriteString(stdin, query)
	if err != nil {
		return fmt.Errorf("failed to write query to stdin: %w", err)
	}

	// Wait for the response to be fully read
	<-responseRead

	return nil
}
