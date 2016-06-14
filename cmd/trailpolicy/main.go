package main

import (
  "fmt"
  "github.com/rcaught/trailpolicy"
  "io/ioutil"
  "os"
)

func main() {
  bytes, _ := ioutil.ReadAll(os.Stdin)

  if cloudtrailRecords, err := trailpolicy.Parse(string(bytes)); err != nil {
    fmt.Println(fmt.Errorf("xxxxx: %s", err.Error()))
  } else {
    if val, err := trailpolicy.CreatePolicy(cloudtrailRecords); err != nil {
      fmt.Println(fmt.Errorf("xxxxx: %s", err.Error()))
    } else {
      if j, err := trailpolicy.CreatePolicyJSON(val); err != nil {
        fmt.Println(fmt.Errorf("xxxxx: %s", err.Error()))
      } else {
        fmt.Print(string(j))
      }
    }
  }
}
