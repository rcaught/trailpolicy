package trailpolicy_test

import (
  "github.com/rcaught/trailpolicy"
  "github.com/stretchr/testify/assert"

  "fmt"
  "io/ioutil"
  "testing"
)

func TestConvertSingle(t *testing.T) {
  bytes, _ := ioutil.ReadFile("fixtures/single.log")

  result, _ := trailpolicy.Convert(bytes)

  expected := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:StopInstances"
      ],
      "Resource": "*"
    }
  ]
}`

  assert.Equal(t, expected, result)
}

func TestConvertMultiple(t *testing.T) {
  bytes, _ := ioutil.ReadFile("fixtures/multiple.log")

  result, _ := trailpolicy.Convert(bytes)

  expected := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:StopInstances",
        "ec2:CreateKeyPair"
      ],
      "Resource": "*"
    }
  ]
}`

	assert.Equal(t, expected, result)
}

func TestConvertError(t *testing.T) {
  bytes, _ := ioutil.ReadFile("fixtures/bad.log")

  result, err := trailpolicy.Convert(bytes)

  resultExpected := ""
  errorExpected := fmt.Errorf("Error parsing Cloudtrail log: invalid character ':' after top-level value")

  assert.Equal(t, resultExpected, result)
  assert.Equal(t, errorExpected, err)
}
