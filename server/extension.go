package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"time"

	"github.com/osquery/osquery-go"
)

const (
	ExitString = "exit"
)

type Query struct {
	SQL string `json:"query"`
}

type Result struct {
	Data interface{} `json:"data"`
}

func main() {
	client, err := osquery.NewClient("/home/sven/.osquery/shell.em", 10*time.Second)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	defer client.Close()

	for {
		query, err := decodeQuery()
		if err != nil {
			if err == io.EOF {
				log.Println("client has disconnected")
				break
			}
			log.Fatalf("Error decoding JSON: %v\n", err)
		}

		if query.SQL == ExitString {
			log.Println("Exit command received, terminating...")
			break
		}

		resp, err := client.Query(query.SQL)
		if err != nil {
			log.Fatalf("Error communicating with osqueryi: %v", err)
		}
		if resp.Status.Code != 0 {
			log.Fatalf("osqueryi returned error: %s", resp.Status.Message)
		}

		err = parseAndSendResult(resp.Response)
		if err != nil {
			log.Fatalf("Error parsing and sending result: %v\n", err)
		}
	}
}

func decodeQuery() (*Query, error) {
	decoder := json.NewDecoder(os.Stdin)
	query := &Query{}
	err := decoder.Decode(query)
	if err != nil {
		return nil, err
	}
	return query, nil
}

func parseAndSendResult(respData interface{}) error {
	var jsonData interface{}

	// Convert respData to JSON
	dataBytes, err := json.Marshal(respData)
	if err != nil {
		return err
	}

	// Unmarshal into interface{}
	err = json.Unmarshal(dataBytes, &jsonData)
	if err != nil {
		return err
	}

	// Create Result with JSON data
	result := &Result{
		Data: jsonData,
	}

	// Send Result as JSON
	return json.NewEncoder(os.Stdout).Encode(result)
}
