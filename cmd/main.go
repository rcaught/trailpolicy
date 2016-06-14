package main

import (
  "encoding/json"
  "fmt"
  "io/ioutil"
  "os"
  "strings"
)

func main() {
  bytes, _ := ioutil.ReadAll(os.Stdin)

  if cloudtrailRecords, err := parse(string(bytes)); err != nil {
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
