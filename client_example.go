package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/fueledByOats/osquery-extension-stdio-json/client"
)

var (
	once            sync.Once
	singletonClient *client.Client
)

func main() {
	clientExample1()
}

func clientExample1() {
	client := &client.Client{}
	err := client.Start("go run /home/sven/go/src/osquery-extension/extension.go --socket /home/sven/.osquery/shell.em")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer client.Stop()

	// Query for users
	result, err := client.SendQuery("SELECT name FROM osquery_registry WHERE registry='table'")
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Users Result:\n", string(result.Data))
	}

	// Query for all tables
	result, err = client.SendQuery("PRAGMA table_info(file)")
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("\nTables Result:\n", string(result.Data))
	}

	_, err = client.SendQuery("exit")
	if err != nil {
		fmt.Println("Error:", err)
	}
}

// retrieve all data types osquery uses
func clientExample2() {
	client := &client.Client{}
	err := client.Start("go run /home/sven/go/src/osquery-extension/extension.go --socket /home/sven/.osquery/shell.em")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer client.Stop()

	// Query for all tables
	result, err := client.SendQuery("SELECT name FROM osquery_registry WHERE registry='table'")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	var tables []map[string]string
	err = json.Unmarshal(result.Data, &tables)
	if err != nil {
		fmt.Println("Error unmarshalling:", err)
		return
	}

	var allTypes []string
	for _, table := range tables {
		tableName := table["name"]
		result, err = client.SendQuery(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}

		var tableInfo []map[string]interface{}
		err = json.Unmarshal(result.Data, &tableInfo)
		if err != nil {
			fmt.Println("Error unmarshalling table info:", err)
			continue
		}

		for _, column := range tableInfo {
			columnType := column["type"].(string)
			if !contains(allTypes, columnType) {
				allTypes = append(allTypes, columnType)
			}
		}
	}

	fmt.Println("All Types:", allTypes)
}

// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}

func clientExample3() {
	fmt.Println("Tables Result:", retrieveJSONDataForTable("users"))
	fmt.Println("Tables Result:", retrieveJSONDataForTable("users"))
}

func retrieveOsqueryTableNames(ctx context.Context) []string {
	/*client := &client.Client{}
	err := client.Start("go run /home/sven/go/src/osquery-extension-ssh-json/server/extension.go --socket /home/sven/.osquery/shell.em")
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}
	defer client.Stop()

	result, err := client.SendQuery("SELECT name FROM osquery_registry WHERE registry='table'")
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}

	var tables []map[string]string
	err = json.Unmarshal(result.Data, &tables)
	if err != nil {
		fmt.Println("Error unmarshalling:", err)
		return nil
	}

	var tableNames []string
	for _, table := range tables {
		tableNames = append(tableNames, table["name"])
	}

	return tableNames*/
	return []string{"users"}
}

func getClient() *client.Client {
	once.Do(func() {
		singletonClient = &client.Client{}
		err := singletonClient.Start("go run /home/sven/go/src/osquery-extension-stdio-json/server/extension.go --socket /home/sven/.osquery/shell.em")
		if err != nil {
			fmt.Println("Error initializing client:", err)
		}
	})
	return singletonClient
}

func retrieveJSONDataForTable(tablename string) string {
	client := getClient()
	query := fmt.Sprintf("SELECT * FROM %s", tablename)
	result, err := client.SendQuery(query)
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}

	return string(result.Data)

}
