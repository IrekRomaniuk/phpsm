package main

import (
	"github.com/IrekRomaniuk/phpsm/utils"
	"fmt"
	"flag"
	"log"
	"os"
	"encoding/json"
	"github.com/cydev/zero"
	"strconv"
	"strings"
)

var (
	//FROMURL from Proofpoint
	FROMURL      = flag.String("from", "https://tap-api-v2.proofpoint.com/v2/siem/all", "Proofpoint URL to pull messages from")
	//TOURL to Phantom
	TOURL     = flag.String("to", "https://10.34.1.110", "Phantom REST endpoint")
	//PRINICIPAL Proofpoint Service Principal
	PRINICIPAL    = flag.String("sp", "", "Proofpoint service principal")
	//SECRET Proofpoint Secret
	SECRET    = flag.String("s", "", "Proofpoint secret")
	//USER Phantom
	USER    = flag.String("u", "admin", "Phantom username")
	//PASS Phantom
	PASS    = flag.String("p", "", "Phantom password")
	//SinceSeconds from the current API server time
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

// go run -ldflags "-X main.Version=`git rev-parse HEAD`" main.go -sp=xxx -s=xxx -p='xxx' -sec=3600
func main() {
	var message utils.Message		
	url := *FROMURL
	data, err  := utils.GetPage(url + "?format=JSON&sinceSeconds=" + *SinceSeconds, 
		*PRINICIPAL, *SECRET)
	if err != nil {
		log.Fatal(err)
	}	
	err = json.Unmarshal(data, &message)
	if err != nil {
		log.Fatal(err)
	}	
	container := utils.Container{
		Description: "Container added via REST API call",
		Label: "proofpoint",
		Name: "threat insight " + (message.QueryEndTime).Format("2006-01-02 15:04:05"),
	}
	cID, err := utils.PostPage(*TOURL + "/rest/container", *USER, *PASS, container)
	if err != nil {
		log.Fatal(err)
	}
	err = addMessageArtifcat(cID, message.MessagesDelivered, "MessagesDelivered")
	if err != nil {
		log.Fatal(err)
	}
	err = addMessageArtifcat(cID, message.MessagesBlocked, "MessagesBlocked")	
	if err != nil {
		log.Fatal(err)
	}
	err = addClickArtifcat(cID, message.ClicksPermitted, "clicksPermitted")	
	if err != nil {
		log.Fatal(err)
	}
	err = addClickArtifcat(cID, message.ClicksBlocked, "clicksBlocked")	
	if err != nil {
		log.Fatal(err)
	}
}

func addMessageArtifcat(cID int64, m utils.Messages, name string) error {
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
				Data: "DATA",  // follow up required https://my.phantom.us/3.0/docs/rest	
				Cef: map[string]string{"sourceAddress": m[i].SenderIP,
					"suser": m[i].Sender,
					"toAddresses": toAddresses,
					"fromAddresses": fromAddresses,
					"subject": m[i].Subject,
					"duser": recipients,
					"externalId": m[i].GUID,
					"malwareScore": strconv.Itoa(m[i].MalwareScore),
					"phishScore": strconv.Itoa(m[i].PhishScore),
					"spamScore": strconv.Itoa(m[i].SpamScore),
					},			
			}
			aID, err := utils.PostPage(*TOURL + "/rest/artifact", *USER, *PASS, artifact)
			if err !=nil {
				return err
			} else {
				fmt.Printf("container id: %d artifact id: %d\n", cID, aID)
			}			
		}		
	}
	return nil
}	

func addClickArtifcat(cID int64, m utils.Clicks, name string) error {
	if !zero.IsZero(m) {
		fmt.Printf(name + ": %d\n", len(m))		
		for i:=0; i < len(m); i++ {								
			artifact := utils.Artifact{
				Description: "Artifact added via REST API call",
				Label: "proofpoint artifact",
				Name: name + " " + strconv.Itoa(i+1),
				Container: cID,
				Data: "DATA",  // follow up required https://my.phantom.us/3.0/docs/rest	
				Cef: map[string]string{"clickIP": m[i].ClickIP,
					"suser": m[i].Sender,
					"url": m[i].URL,
					"sourceAddress": m[i].SenderIP,
					"classification": m[i].Classification,
					"duser": m[i].Recipient,
					"externalId": m[i].GUID,
					"threatID": m[i].ThreatID,
					"threatURL": m[i].ThreatURL,
					"userAgent": m[i].UserAgent,
					},			
			}
			aID, err := utils.PostPage(*TOURL + "/rest/artifact", *USER, *PASS, artifact)
			if err !=nil {
				return err
			} else {
				fmt.Printf("container id: %d artifact id: %d\n", cID, aID)
			}			
		}		
	}
	return nil
}