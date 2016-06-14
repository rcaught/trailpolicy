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

// Parses a Cloudtrail log file
func Parse(cloudtrailJSON string) (*[]cloudtrailRecord, error) {
  trail := cloudtrailLog{}

  if err := json.Unmarshal([]byte(cloudtrailJSON), &trail); err != nil {
    return nil, fmt.Errorf("Error unmarshaling Cloudtrail JSON: %s", err.Error())
  }

  return &trail.Records, nil
}

// Creates a struct that represents a Policy Document
func CreatePolicy(r *[]cloudtrailRecord) (policyDocument, error) {
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

// Turns a struct representation of a Policy Document into the actual JSON
func CreatePolicyJSON(doc policyDocument) ([]byte, error) {
  result, err := json.MarshalIndent(doc, "", "  ")

  if err != nil {
    return nil, fmt.Errorf("xxxxx: %s", err.Error())
  }

  return result, nil
}
