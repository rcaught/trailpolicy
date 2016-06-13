package main

import (
  "encoding/json"
  "fmt"
  "strings"
)

type cloudtrailLog struct {
  Records []cloudtrailRecord
}

type cloudtrailRecord struct {
  EventVersion    string
  UserIdentity    map[string]interface{}
  EventTime       string
  EventSource     string
  EventName       string
  UserAgent       string
  SourceIPAddress string
  AwsRegion       string
}

type policyDocument struct {
  Version   string
  Statement []policyStatement
}

type policyStatement struct {
  Effect   string
  Action   action
  Resource string
}

type action []string

var data = `
{
    "Records": [{
        "eventVersion": "1.0",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "EX_PRINCIPAL_ID",
            "arn": "arn:aws:iam::123456789012:user/Alice",
            "accountId": "123456789012",
            "accessKeyId": "EXAMPLE_KEY_ID",
            "userName": "Alice"
        },
        "eventTime": "2014-03-06T21:01:59Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "StopInstances",
        "awsRegion": "us-west-2",
        "sourceIPAddress": "205.251.233.176",
        "userAgent": "ec2-api-tools 1.6.12.2",
        "requestParameters": {
            "instancesSet": {
                "items": [{
                    "instanceId": "i-ebeaf9e2"
                }]
            },
            "force": false
        },
        "responseElements": {
            "instancesSet": {
                "items": [{
                    "instanceId": "i-ebeaf9e2",
                    "currentState": {
                        "code": 64,
                        "name": "stopping"
                    },
                    "previousState": {
                        "code": 16,
                        "name": "running"
                    }
                }]
            }
        }
    }
  ]
}`

func main() {
  if cloudtrailRecords, err := parse(data); err != nil {
    fmt.Println(fmt.Errorf("xxxxx: %s", err.Error()))
  } else {
    if val, err := createPolicy(cloudtrailRecords); err != nil {
      fmt.Println(fmt.Errorf("xxxxx: %s", err.Error()))
    } else {
      if j, err := createPolicyJSON(val); err != nil {
        fmt.Println(fmt.Errorf("xxxxx: %s", err.Error()))
      } else {
        fmt.Print(string(j))
      }
    }
  }
}

func parse(cloudtrailJSON string) (*[]cloudtrailRecord, error) {
  trail := cloudtrailLog{}

  if err := json.Unmarshal([]byte(cloudtrailJSON), &trail); err != nil {
    return nil, fmt.Errorf("Error unmarshaling Cloudtrail JSON: %s", err.Error())
  }

  return &trail.Records, nil
}

func createPolicy(r *[]cloudtrailRecord) (policyDocument, error) {
  actions := action{}

  for _, val := range *r {
    service := strings.Split(val.EventSource, ".")[0]
    action := service + ":" + val.EventName

    actions = append(actions, action)
  }

  document := policyDocument{
    Version:   "Current date",
    Statement: []policyStatement{{Effect: "Allow", Resource: "*", Action: actions}}}

  return document, nil
}

func createPolicyJSON(doc policyDocument) ([]byte, error) {
  result, err := json.MarshalIndent(doc, "", "  ")

  if err != nil {
    return nil, fmt.Errorf("xxxxx: %s", err.Error())
  }

  return result, nil
}
