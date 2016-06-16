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
	EventSource string
	EventName   string
}

type policyDocument struct {
	Version   string
	Statement []policyStatement
}

type policyStatement struct {
	Effect   string
	Action   actions
	Resource string
}

type actions []string

func parse(cloudtrailJSON []byte) (*[]cloudtrailRecord, error) {
	trail := cloudtrailLog{}

	if err := json.Unmarshal(cloudtrailJSON, &trail); err != nil {
		return nil, err
	}

	return &trail.Records, nil
}

func deriveAction(record cloudtrailRecord) string {
	service := strings.Split(record.EventSource, ".")[0]

	return service + ":" + record.EventName
}

func createPolicy(r *[]cloudtrailRecord) (*policyDocument, error) {
	actions := actions{}

	for _, record := range *r {
		action := deriveAction(record)
		actions = append(actions, action)
	}

	document := policyDocument{
		Version:   "2012-10-17",
		Statement: []policyStatement{{Effect: "Allow", Resource: "*", Action: actions}}}

	return &document, nil
}

func createPolicyJSON(document *policyDocument) (*[]byte, error) {
	result, err := json.MarshalIndent(*document, "", "  ")

	if err != nil {
		return nil, err
	}

	return &result, nil
}

// Convert takes a JSON based Cloudtrail log and returns a JSON based IAM Policy Document
func Convert(cloudtrailJSON []byte) (string, error) {
	cloudtrailRecords, err := parse(cloudtrailJSON)

	if err != nil {
		return "", fmt.Errorf("Error parsing Cloudtrail log: %s", err.Error())
	}

	policy, err := createPolicy(cloudtrailRecords)

	if err != nil {
		return "", fmt.Errorf("Error creating Policy Document: %s", err.Error())
	}

	json, err := createPolicyJSON(policy)

	if err != nil {
		return "", fmt.Errorf("Error encoding Policy Document: %s", err.Error())
	}

	return string(*json), nil
}
