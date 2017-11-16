package utils

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"time"
	"bytes"
	"encoding/json"
)

/*type Message struct {
	QueryEndTime time.Time `json:"queryEndTime"`
	MessagesDelivered []interface{} `json:"messagesDelivered"`
	MessagesBlocked []interface{} `json:"messagesBlocked"`
	ClicksPermitted []interface{} `json:"clicksPermitted"`
	ClicksBlocked []interface{} `json:"clicksBlocked"`
}*/
type Message struct {
	QueryEndTime      time.Time     `json:"queryEndTime"`
	ClicksPermitted []struct {
		URL            string    `json:"url"`
		Classification string    `json:"classification"`
		ClickTime      time.Time `json:"clickTime"`
		ThreatTime     time.Time `json:"threatTime"`
		UserAgent      string    `json:"userAgent"`
		CampaignID     string    `json:"campaignId"`
		ClickIP        string    `json:"clickIP"`
		Sender         string    `json:"sender"`
		Recipient      string    `json:"recipient"`
		SenderIP       string    `json:"senderIP"`
		GUID           string    `json:"GUID"`
		ThreatID       string    `json:"threatID"`
		ThreatURL      string    `json:"threatURL"`
		ThreatStatus   string    `json:"threatStatus"`
		MessageID      string    `json:"messageID"`
	} `json:"clicksPermitted"`
	ClicksBlocked []struct {
		URL            string    `json:"url"`
		Classification string    `json:"classification"`
		ClickTime      time.Time `json:"clickTime"`
		ThreatTime     time.Time `json:"threatTime"`
		UserAgent      string    `json:"userAgent"`
		CampaignID     string    `json:"campaignId"`
		ClickIP        string    `json:"clickIP"`
		Sender         string    `json:"sender"`
		Recipient      string    `json:"recipient"`
		SenderIP       string    `json:"senderIP"`
		GUID           string    `json:"GUID"`
		ThreatID       string    `json:"threatID"`
		ThreatURL      string    `json:"threatURL"`
		ThreatStatus   string    `json:"threatStatus"`
		MessageID      string    `json:"messageID"`
	} `json:"clicksBlocked"`
	MessagesDelivered []struct {
		SpamScore      int `json:"spamScore"`
		PhishScore     int `json:"phishScore"`
		ThreatsInfoMap []struct {
			ThreatID       string      `json:"threatID"`
			ThreatStatus   string      `json:"threatStatus"`
			Classification string      `json:"classification"`
			ThreatURL      string      `json:"threatUrl"`
			ThreatTime     time.Time   `json:"threatTime"`
			Threat         string      `json:"threat"`
			CampaignID     interface{} `json:"campaignID"`
			ThreatType     string      `json:"threatType"`
		} `json:"threatsInfoMap"`
		MessageTime      time.Time     `json:"messageTime"`
		ImpostorScore    float64       `json:"impostorScore"`
		MalwareScore     int           `json:"malwareScore"`
		Cluster          string        `json:"cluster"`
		Subject          interface{}   `json:"subject"`
		QuarantineFolder interface{}   `json:"quarantineFolder"`
		QuarantineRule   interface{}   `json:"quarantineRule"`
		PolicyRoutes     []string      `json:"policyRoutes"`
		ModulesRun       []string      `json:"modulesRun"`
		MessageSize      int           `json:"messageSize"`
		HeaderFrom       string        `json:"headerFrom"`
		HeaderReplyTo    interface{}   `json:"headerReplyTo"`
		FromAddress      []string      `json:"fromAddress"`
		CcAddresses      []interface{} `json:"ccAddresses"`
		ReplyToAddress   []interface{} `json:"replyToAddress"`
		ToAddresses      []interface{} `json:"toAddresses"`
		Xmailer          interface{}   `json:"xmailer"`
		MessageParts     []struct {
			Disposition   string `json:"disposition"`
			Sha256        string `json:"sha256"`
			Md5           string `json:"md5"`
			Filename      string `json:"filename"`
			SandboxStatus string `json:"sandboxStatus"`
			OContentType  string `json:"oContentType"`
			ContentType   string `json:"contentType"`
		} `json:"messageParts"`
		CompletelyRewritten bool     `json:"completelyRewritten"`
		QID                 string   `json:"QID"`
		GUID                string   `json:"GUID"`
		Sender              string   `json:"sender"`
		Recipient           []string `json:"recipient"`
		SenderIP            string   `json:"senderIP"`
		MessageID           string   `json:"messageID"`
	} `json:"messagesDelivered"`
	MessagesBlocked []struct {
		SpamScore      int `json:"spamScore"`
		PhishScore     int `json:"phishScore"`
		ThreatsInfoMap []struct {
			ThreatID       string      `json:"threatID"`
			ThreatStatus   string      `json:"threatStatus"`
			Classification string      `json:"classification"`
			ThreatURL      string      `json:"threatUrl"`
			ThreatTime     time.Time   `json:"threatTime"`
			Threat         string      `json:"threat"`
			CampaignID     interface{} `json:"campaignID"`
			ThreatType     string      `json:"threatType"`
		} `json:"threatsInfoMap"`
		MessageTime      time.Time     `json:"messageTime"`
		ImpostorScore    float64       `json:"impostorScore"`
		MalwareScore     int           `json:"malwareScore"`
		Cluster          string        `json:"cluster"`
		Subject          interface{}   `json:"subject"`
		QuarantineFolder interface{}   `json:"quarantineFolder"`
		QuarantineRule   interface{}   `json:"quarantineRule"`
		PolicyRoutes     []string      `json:"policyRoutes"`
		ModulesRun       []string      `json:"modulesRun"`
		MessageSize      int           `json:"messageSize"`
		HeaderFrom       string        `json:"headerFrom"`
		HeaderReplyTo    interface{}   `json:"headerReplyTo"`
		FromAddress      []string      `json:"fromAddress"`
		CcAddresses      []interface{} `json:"ccAddresses"`
		ReplyToAddress   []interface{} `json:"replyToAddress"`
		ToAddresses      []string      `json:"toAddresses"`
		Xmailer          string        `json:"xmailer"`
		MessageParts     []struct {
			Disposition   string `json:"disposition"`
			Sha256        string `json:"sha256"`
			Md5           string `json:"md5"`
			Filename      string `json:"filename"`
			SandboxStatus string `json:"sandboxStatus"`
			OContentType  string `json:"oContentType"`
			ContentType   string `json:"contentType"`
		} `json:"messageParts"`
		CompletelyRewritten bool     `json:"completelyRewritten"`
		QID                 string   `json:"QID"`
		GUID                string   `json:"GUID"`
		Sender              string   `json:"sender"`
		Recipient           []string `json:"recipient"`
		SenderIP            string   `json:"senderIP"`
		MessageID           string   `json:"messageID"`
	} `json:"messagesBlocked"`
}

type Container struct {
	Id int64
	Version string
	Label string `json:"label"`
	Name string `json:"name"`
	Source_data_identifier string
	Description string `json:"description"`
	Status string
	Sensitivity string
	Severity string
	Create_time time.Time
	Start_time time.Time
	End_time time.Time
	Due_time time.Time
	Close_time time.Time
	Kill_chain string
	Owner string
	Hash string
	Tags []string
	Asset_name string
	Artifact_update_time time.Time
	Container_update_time time.Time
	Ingest_app_id string
	Data interface{}
	Artifact_count int
}
type Artifact struct {	
	Id int64
	Version int
	Name string `json:"name"`
	Label string `json:"label"`
	Source_data_identifier string `json:"source_data_identifier"`
	Create_time time.Time
	Start_time time.Time
	End_time time.Time
	Severity string
	Type string
	Kill_chain string
	Hash string
	Cef interface{}
	Container int64 `json:"container_id"`
	Description string `json:"description"`
	Tags []string
	Data interface{}
}
type Response struct {
	ID int64 `json:"id"`
	Success bool `json:"success"` 
}

// GetPage from url and return body as string
func GetPage(url, user, pass string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", url, nil)
    req.SetBasicAuth(user, pass)

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}
	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}
	resp.Body.Close()
	return htmlData, nil
}

// PostPage to url
func PostPage(url, user, pass string, data interface{}) (int64, error) {
	var response Response
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	body := new(bytes.Buffer)
	json.NewEncoder(body).Encode(data)  // err:=	
	req, err := http.NewRequest("POST", url, body)
	req.SetBasicAuth(user, pass)
	//req.Header.Set("ph-auth-token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	err = json.Unmarshal(htmlData, &response)
	if err != nil {
		return 0, err
	}
	return response.ID, nil
}