package main

import (
	"log"
	"flag"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"io/ioutil"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

type FileContent struct {
	Content string
	Path    string
}

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
)

func main() {
	flag.Parse()
	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}
	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"file_content",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(table.NewPlugin("file_content", FileContentColumns(), FileContentGenerate))
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func FileContentColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("content"),
		table.TextColumn("path"),
	}
}

func FileContentGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {

	path := ""
	wildcard := false

	if constraintList, present := queryContext.Constraints["path"]; present {
		// 'path' is in the where clause
		for _, constraint := range constraintList.Constraints {
			// LIKE
			if constraint.Operator == table.OperatorLike {
				path = constraint.Expression
				wildcard = true
			}
			// =
			if constraint.Operator == table.OperatorEquals {
				path = constraint.Expression
				wildcard = false
			}
		}
	}
	var results []map[string]string
	output, err := processFile(path, wildcard)
	if err != nil {
		return results, err
	}

	for _, item := range output {
		results = append(results, map[string]string{
			"content": item.Content,
			"path":    item.Path,
		})
	}

	return results, nil
}

func processFile(path string, wildcard bool) ([]FileContent, error) {
	var output []FileContent

	if wildcard {
		replacedPath := strings.ReplaceAll(path, "%", "*")

		files, err := filepath.Glob(replacedPath)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			content, err := readFileContent(file)
			if err != nil {
				return nil, err
			}
			output = append(output, content)
		}
	} else {
		content, err := readFileContent(path)
		if err != nil {
			return nil, err
		}
		output = append(output, content)
	}

	return output, nil
}

func readFileContent(path string) (FileContent, error) {
	if !fileExists(path) {
		err := errors.New("File does not exist")
		return FileContent{}, err
	}

	contentBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return FileContent{}, err
	}

	content := string(contentBytes)
	return FileContent{Path: path, Content: content}, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
