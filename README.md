## PHPSM
### Proofpoint [SIEM](https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API) to [Phantom](https://my.phantom.us/3.0/docs/rest)
![Proofpoint Threat Insight](./proofpoint.PNG "Proofpoint Threat Insight")
#### REST API POST of Proofpoint SIEM messages to Phantom
![Mission Control](./phpsm.PNG "Phantom Proofpoint")
Parameters:

```
Copyright 2017 @IrekRomaniuk. All jdk-rights reversed.
Usage:
  -from string
        Proofpoint URL to pull messages from (default "https://tap-api-v2.proofpoint.com/v2/siem/all")
  -p string
        Phantom password
  -s string
        Proofpoint secret
  -sec string
        a time window in seconds from the current API server time (default "600")
  -sp string
        Proofpoint service principal
  -to string
        Phantom REST endpoint
  -u string
        Phantom username (default "admin")
  -v    Prints current version
  ```

Example of use:

```
./phpsm_lin -sp=xxx -s=yyy -p='password' -sec=600
MessagesDelivered: 5
container id: 17959 artifact id: 96034
container id: 17959 artifact id: 96035
container id: 17959 artifact id: 96036
container id: 17959 artifact id: 96037
container id: 17959 artifact id: 96038
MessagesBlocked: 1
container id: 17959 artifact id: 96039
```