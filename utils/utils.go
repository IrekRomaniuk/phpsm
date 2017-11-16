package utils

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"time"
	"bytes"
	"encoding/json"
)
//Clicks https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API
type Clicks []struct {
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
} 
//Messages https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API
type Messages []struct {
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
	Subject          string        `json:"subject"`
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
	ToAddresses      []string `json:"toAddresses"`
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
} 
//Message https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API
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
		Subject          string  	   `json:"subject"`
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
		ToAddresses      []string `json:"toAddresses"`
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
		Subject          string        `json:"subject"`
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
	} `json:"messagesBlocked"`
}
//Container Phantom https://my.phantom.us/3.0/docs/automation/containers
type Container struct {
	ID int64
	Version string
	Label string `json:"label"`
	Name string `json:"name"`
	Sourcedataidentifier string
	Description string `json:"description"`
	Status string
	Sensitivity string
	Severity string
	Createtime time.Time
	Starttime time.Time
	Endtime time.Time
	Duetime time.Time
	Closetime time.Time
	Killchain string
	Owner string
	Hash string
	Tags []string
	Assetname string
	Artifactupdatetime time.Time
	Containerupdatetime time.Time
	Ingestappid string
	Data map[string]string
	Artifactcount int
}
//Artifact Phantom https://my.phantom.us/3.0/docs/automation/artifacts
type Artifact struct {	
	ID int64
	Version int
	Name string `json:"name"`
	Label string `json:"label"`
	Sourcedataidentifier string `json:"source_data_identifier"`
	Createtime time.Time
	Starttime time.Time
	Endtime time.Time
	Severity string
	Type string
	Killchain string
	Hash string
	Cef map[string]string `json:"cef"`
	Container int64 `json:"container_id"`
	Description string `json:"description"`
	Tags []string
	Data string `json:"data"`
}
//Response from Phantom 
type Response struct {
	ID int64 `json:"id"`
	Success bool `json:"success"` 
}

// GetPage from Proofpoint and return body as string
func GetPage(url, user, pass string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []byte{}, err
	}
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

// PostPage to Phantom and return container id
func PostPage(url, user, pass string, data interface{}) (int64, error) {
	var response Response
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(data)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return 0, err
	}
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