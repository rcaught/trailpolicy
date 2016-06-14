package trailpolicy

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

func parse(cloudtrailJSON []byte) (*[]cloudtrailRecord, error) {
  trail := cloudtrailLog{}

  if err := json.Unmarshal(cloudtrailJSON, &trail); err != nil {
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
    Version:   "2012-10-17",
    Statement: []policyStatement{{Effect: "Allow", Resource: "*", Action: actions}}}

  return document, nil
}

func createPolicyJSON(doc policyDocument) ([]byte, error) {
  result, err := json.MarshalIndent(doc, "", "  ")

  if err != nil {
    return nil, fmt.Errorf("Error marshaling Policy Document: %s", err.Error())
  }

  return result, nil
}

// Convert takes a JSON Cloudtrail log and returns a JSON based IAM Policy Document
func Convert(cloudtrailJSON []byte) ([]byte, error) {
  if cloudtrailRecords, err := parse(cloudtrailJSON); err != nil {
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
