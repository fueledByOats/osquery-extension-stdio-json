package client

import "fmt"

func main() {
	client := &Client{}
	err := client.Start("go run /home/sven/go/src/osquery-extension-ssh-json/server/extension.go --socket /home/sven/.osquery/shell.em")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer client.Stop()

	// Query for users
	result, err := client.SendQuery("select * from users")
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Users Result:", string(result.Data))
	}

	// Query for processes
	result, err = client.SendQuery("SELECT name FROM osquery_registry WHERE registry='table'")
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Processes Result:", string(result.Data))
	}

	/*_, err = client.SendQuery(ExitString)
	if err != nil {
		fmt.Println("Error:", err)
	}*/
}
