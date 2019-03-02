# trailpolicy [![Build Status](https://travis-ci.org/rcaught/trailpolicy.svg?branch=master)](https://travis-ci.org/rcaught/trailpolicy) [![GoDoc](https://godoc.org/github.com/rcaught/trailpolicy?status.svg)](https://godoc.org/github.com/rcaught/trailpolicy)

Derive an AWS IAM Policy Document from actions found within Cloudtrail logs.

## Installation
##### Go
```
$ go get github.com/rcaught/trailpolicy/...
```
##### MacOS
```
$ curl -Ls https://github.com/rcaught/trailpolicy/releases/latest/download/macos.zip > /tmp/trailpolicy.zip
$ unzip /tmp/trailpolicy.zip -d /usr/local/bin
```
##### Linux
```
$ curl -Ls https://github.com/rcaught/trailpolicy/releases/latest/download/linux.zip > /tmp/trailpolicy.zip
$ unzip /tmp/trailpolicy.zip -d /usr/local/bin
```

## Usage
```
$ cat cloudtrail.log | trailpolicy > policydocument.json
```

## Example
``` bash
$ cat cloudtrail.log
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
}

$ cat cloudtrail.log | trailpolicy
{
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
}
```
