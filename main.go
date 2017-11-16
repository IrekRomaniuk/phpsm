package main

import (
	"github.com/IrekRomaniuk/phpsm/utils"
	"fmt"
	"flag"
	"os"
	"encoding/json"
	"github.com/cydev/zero"
	"strconv"
	"strings"
)

var (
	//FROMURL from Proofpoint
	FROMURL      = flag.String("from", "https://tap-api-v2.proofpoint.com/v2/siem/all", "Proofpoint URL to pull IP messages from")
	//TOURL to Phantom
	TOURL     = flag.String("to", "https://phantom-dev/rest/handler/restdatasource_95e3bcff-bfca-454d-b59e-768da6280c38/proofpoint", "Phantom REST endpoint")
	//PRINICIPAL Proofpoint Service Principal
	PRINICIPAL    = flag.String("sp", "", "Service Principal")
	//SECRET Proofpoint Secret
	SECRET    = flag.String("s", "", "Secret")
	//USER Phantom
	USER    = flag.String("u", "admin", "Phantom username")
	//PASS Phantom
	PASS    = flag.String("p", "", "Phantom password")
	//sinceSeconds from the current API server time
	SinceSeconds    = flag.String("sec", "600", "a time window in seconds from the current API server time")
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

// go run main.go -sp=xxx -s=xxx -p='xxx' -sec=3600
func main() {
	var message utils.Message		
	url := "https://tap-api-v2.proofpoint.com/v2/siem/all"
	data, err  := utils.GetPage(url + "?format=JSON&sinceSeconds=" + *SinceSeconds, 
		*PRINICIPAL, *SECRET)
	if err != nil {
		os.Exit(0)
	}	
	err = json.Unmarshal(data, &message)
	if err != nil {
		os.Exit(0)
	}	
	container := utils.Container{
		Description: "Container added via REST API call",
		Label: "proofpoint",
		Name: "threat insight " + (message.QueryEndTime).Format("2006-01-02 15:04:05"),
	}
	cID, err := utils.PostPage("https://10.34.1.110/rest/container", *USER, *PASS, container)
	if err != nil {
		os.Exit(0)
	}
	addMessageArtifcat(cID, message.MessagesDelivered, "MessagesDelivered")
	addMessageArtifcat(cID, message.MessagesBlocked, "MessagesBlocked")	
}

func addMessageArtifcat(cID int64, m utils.Messages, name string) {
	if !zero.IsZero(m) {
		fmt.Printf(name + ": %d\n", len(m))		
		for i:=0; i < len(m); i++ {			
			//data, _ = json.Marshal(map[string]string{"HeaderFrom": message.MessagesBlocked[i].HeaderFrom})
			//fmt.Println(string(data))
			recipients := strings.Join(m[i].Recipient, ",")
			toAddresses := strings.Join(m[i].ToAddresses, ",")
			fromAddresses := strings.Join(m[i].FromAddress, ",")
			artifact := utils.Artifact{
				Description: "Artifact added via REST API call",
				Label: "proofpoint artifact",
				Name: name + " " + strconv.Itoa(i+1),
				Container: cID,
				Data: "DATA",	
				Cef: map[string]string{"sourceAddress": m[i].SenderIP,
					"suser": m[i].Sender,
					"toAddresses": toAddresses,
					"fromAddresses": fromAddresses,
					//"subject": message.MessagesBlocked[i].Subject,
					"duser": recipients,
					"externalId": m[i].GUID,
					"malwareScore": strconv.Itoa(m[i].MalwareScore),
					"phishScore": strconv.Itoa(m[i].PhishScore),
					"spamScore": strconv.Itoa(m[i].SpamScore),
					},			
			}
			aID, _ := utils.PostPage("https://10.34.1.110/rest/artifact", *USER, *PASS, artifact)
			fmt.Printf("container id: %d artifact id: %d\n", cID, aID)
		}		
	}
}	