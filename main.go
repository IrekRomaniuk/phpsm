package main

import (
	"github.com/IrekRomaniuk/phpsm/utils"
	"fmt"
	"flag"
	"os"
	"encoding/json"
	"github.com/cydev/zero"
)

var (
	//FROMURL from Proofpoint
	FROMURL      = flag.String("from", "https://tap-api-v2.proofpoint.com/v2/siem/all", "Proofpoint URL to pull IP messages from")
	//TOURL to Phantom
	TOURL     = flag.String("to", "https://phantom-dev/rest/handler/restdatasource_95e3bcff-bfca-454d-b59e-768da6280c38/proofpoint", "Phantom REST endpoint")
	//FORMAT os JSON or syslog
	//FORMAT    = flag.String("f", "JSON", "the format in which data is returned")
	//PRINICIPAL Proofpoint Service Principal
	PRINICIPAL    = flag.String("sp", "", "Service Principal")
	//SECRET Proofpoint Secret
	SECRET    = flag.String("s", "", "Secret")
	//USER Phantom
	USER    = flag.String("u", "admin", "Phantom username")
	//PASS Phantom
	PASS    = flag.String("p", "", "Phantom password")
	//sinceSeconds from the current API server time
	sinceSeconds    = flag.String("sec", "600", "a time window in seconds from the current API server time")
	//sinceTime is the data retrieval period
	//sinceTime     = flag.String("t", "", "ISO8601 date representing the start of the data retrieval period")
	version   = flag.Bool("v", false, "Prints current version")
	// Version : Program version
	Version   = "No Version Provided" 
	// BuildTime : Program build time
	BuildTime = ""
)

func init() {
	flag.Usage = func() {
		fmt.Printf("Copyright 2017 @IrekRomaniuk. All jdk-rights reversed.\n")
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *version {
		fmt.Printf("App Version: %s\nBuild Time : %s\n", Version, BuildTime)
		os.Exit(0)
	}	
}

func main() {
	var message utils.Message		
	//url="https://tap-api-v2.proofpoint.com/v2/siem/all"
	data, _ := utils.GetPage("https://tap-api-v2.proofpoint.com/v2/siem/all?format=JSON&sinceSeconds=600", 
		*PRINICIPAL, *SECRET)
	json.Unmarshal(data, &message)  // err:=
	fmt.Printf("QueryEndTime: %s\nMessagesDelivered: %v\nMessagesBlocked: %v\nClicksPermitted: %v\nClicksBlocked: %v\n", 
		message.QueryEndTime, message.MessagesDelivered, message.MessagesBlocked,
		message.ClicksPermitted, message.ClicksBlocked)
	if !zero.IsZero(message.MessagesDelivered) {
		fmt.Printf("MessagesDelivered SpamScore: %d", message.MessagesDelivered[0].SpamScore)		
	}
	container := utils.Container{
		Description: "Container added via REST API call",
		Label: "proofpoint",
		Name: "threat insight " + (message.QueryEndTime).Format("2006-01-02 15:04:05"),
	}
	cID, _ := utils.PostPage("https://10.34.1.110/rest/container", *USER, *PASS, container)
	artifact := utils.Artifact{
		Description: "Artifact added via REST API call",
		Label: "proofpoint artifact",
		Name: "test Artifact",
		Container: cID,
	}
	aID, _ := utils.PostPage("https://10.34.1.110/rest/artifact", *USER, *PASS, artifact)
	fmt.Printf("container id: %d artifact id: %d\n", cID, aID)
}