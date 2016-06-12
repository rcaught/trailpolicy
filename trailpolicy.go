package main

import "fmt"

type cloudtrailLog struct {
  Records []cloudtrailRecord
}

type cloudtrailRecord struct {
  EventVersion       string
  UserIdentity       map[string]interface{}
  EventTime          string
  EventSource        string
  EventName          string
  UserAgent          string
  SourceIPAddress    string
  AwsRegion          string
}

func main() {
  Parse()
  CreatePolicy()
}

func Parse() {

}

func CreatePolicy() {

}
