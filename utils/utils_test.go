package utils

import (
	"testing"
	"fmt"
	//"os"
	"flag"
)

var (
	user = flag.String("u", "", "user")
	pass = flag.String("p", "", "pass")
	token = flag.String("t", "", "token")
)

//TestGetPage : go test -run TestGetPage -args -u=user -p=pass
func TestGetPage(t *testing.T) {
	fmt.Printf("user: %s pass: %s", *user, *pass)
	data, _ := GetPage("https://tap-api-v2.proofpoint.com/v2/siem/all?format=JSON&sinceSeconds=60", 
		*user, *pass)
		
	fmt.Println(string(data))
	//fmt.Println(os.Getenv("USER"), os.Getenv("PASS"))	

}
//TestPostPage : go test -run TestPostPage -args -u=admin -p='password'
func TestPostPage(t *testing.T) {
	container := Container{
		Description: "Test container added via REST API call",
		Label: "proofpoint",
		Name: "test",
	}
	/*var container = []byte(`{"description":"Test container added via REST API call", 
		"label":"proofpoint", "name":"test"}`)*/
	fmt.Printf("user: %s pass: %s\n", *user, *pass)
	data, _ := PostPage("https://10.34.1.110/rest/container", *user, *pass, container)
		
	fmt.Println(string(data))

}