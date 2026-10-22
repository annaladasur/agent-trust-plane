#!/usr/bin/env python3
"""
Seed Google Online Boutique sample microservices into local Gitea (Option 2: 4 Synthetic Repos)
Creates 4 microservices with real CVEs declared on Slide 5:
  1. frontend (Go): CVE-2023-44487 (HTTP/2 Rapid Reset in golang.org/x/net v0.16.0), GHSA-m425-mq94-257g (google.golang.org/grpc v1.58.2)
  2. payments (Go): CVE-2023-48795 (Terrapin attack in golang.org/x/crypto v0.14.0), google.golang.org/grpc v1.58.2
  3. recommendations (Python): CVE-2023-43804 & CVE-2023-45803 (urllib3 1.26.17), requests 2.31.0
  4. platform (Go / K8s manifests): k8s.io/client-go v0.28.2, deployment manifests
"""

import base64
import json
import os
import urllib.request
import urllib.error

from gitea_auth import admin_auth

GITEA_URL = os.environ.get("GITEA_URL", "http://localhost:3030/api/v1")

def gitea_api(endpoint: str, method: str = "GET", data: dict = None):
    url = f"{GITEA_URL}{endpoint}"
    headers = {
        "Authorization": f"Basic {admin_auth()}",
        "Content-Type": "application/json"
    }
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        return {"error": e.code, "message": err_msg}

def create_or_update_file(repo: str, file_path: str, content_str: str, message: str):
    b64_content = base64.b64encode(content_str.encode("utf-8")).decode("ascii")
    payload = {
        "content": b64_content,
        "message": message,
        "branch": "main"
    }
    # Check if file exists
    check = gitea_api(f"/repos/online-boutique/{repo}/contents/{file_path}")
    if "sha" in check:
        payload["sha"] = check["sha"]
        res = gitea_api(f"/repos/online-boutique/{repo}/contents/{file_path}", method="PUT", data=payload)
    else:
        res = gitea_api(f"/repos/online-boutique/{repo}/contents/{file_path}", method="POST", data=payload)
    print(f"  -> File {repo}/{file_path}: {'OK' if 'content' in res else res.get('message', 'done')}")

def main():
    print("============================================================")
    print("Seeding 4 Online Boutique Synthetic Microservices in Gitea")
    print("Option 2 (Declared on Slide 5): 4 Microservices with Real CVEs")
    print("============================================================")

    # 1. Frontend (Go service with Rapid Reset advisory set: golang.org/x/net v0.16.0 & google.golang.org/grpc v1.58.2)
    print("\n[1/4] Populating online-boutique/frontend (Go)...")
    frontend_mod = """module github.com/GoogleCloudPlatform/microservices-demo/src/frontend

go 1.21

require (
	github.com/google/uuid v1.3.1
	github.com/gorilla/mux v1.8.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.3
	go.opentelemetry.io/otel v1.19.0
	golang.org/x/net v0.16.0 // CVE-2023-44487 (HTTP/2 Rapid Reset)
	google.golang.org/grpc v1.58.2 // GHSA-m425-mq94-257g (Rapid Reset)
)

require (
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	go.opentelemetry.io/otel/metric v1.19.0 // indirect
	go.opentelemetry.io/otel/trace v1.19.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230711160842-782d3b101e98 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
"""
    frontend_main = """package main

import (
	"fmt"
	"net/http"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "github.com/google/uuid"
	_ "github.com/pkg/errors"
	_ "go.opentelemetry.io/otel"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Online Boutique Frontend Service v1.0")
	})
	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	_ = http2.ConfigureServer(server, &http2.Server{})
	_ = grpc.WithTransportCredentials(insecure.NewCredentials())
	logrus.Info("Frontend listening on port 8080")
	server.ListenAndServe()
}
"""
    frontend_sum = """github.com/davecgh/go-spew v1.1.0/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/go-logr/logr v1.2.2/go.mod h1:jdQByPbusPIv2/zmleS9BjJVeZ6kBagPoEUsqbVz/1A=
github.com/go-logr/logr v1.2.4 h1:g01GSCwiDw2xSZfjJ2/T9M+S6pFdcNtFYsp+Y43HYDQ=
github.com/go-logr/logr v1.2.4/go.mod h1:jdQByPbusPIv2/zmleS9BjJVeZ6kBagPoEUsqbVz/1A=
github.com/go-logr/stdr v1.2.2 h1:hSWxHoqTgW2S2qGc0LTAI563KZ5YKYRhT3MFKZMbjag=
github.com/go-logr/stdr v1.2.2/go.mod h1:mMo/vtBO5dYbehREoey6XUKy/eSumjCCveDpRre4VKE=
github.com/golang/protobuf v1.5.0/go.mod h1:FsONVRAS9T7sI+LIUmWTfcYkHO4aIWwzhcaSAoJOfIk=
github.com/golang/protobuf v1.5.3 h1:KhyjKVUg7Usr/dYsdSqoFveMYd5ko72D+zANwlG1mmg=
github.com/golang/protobuf v1.5.3/go.mod h1:XVQd3VNwM+JqD3oG2Ue2ip4fOMUkwXdXDdiuN0vRsmY=
github.com/google/go-cmp v0.5.5/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/go-cmp v0.5.9 h1:O2Tfq5qg4qc4AmwVlvv0oLiVAGB7enBSJ2x2DqQFi38=
github.com/google/go-cmp v0.5.9/go.mod h1:17dUlkBOakJ0+DkrSSNjCkIjxS6bF9zb3elmeNGIjoY=
github.com/google/uuid v1.3.1 h1:KjJaJ9iWZ3jOFZIf1Lqf4laDRCasjl0BCmnEGxkdLb4=
github.com/google/uuid v1.3.1/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/gorilla/mux v1.8.0 h1:i40aqfkR1h2SlN9hojwV5ZA91wcXFOvkdNIeFDP5koI=
github.com/gorilla/mux v1.8.0/go.mod h1:DVbg23sWSpFRCP0SfiEN6jmj59UnW/n46BH5rLB71So=
github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/sirupsen/logrus v1.9.3 h1:dueUQJ1C2q9oE3F7wvmSGAaVtTmUizReu6fjN8uqzbQ=
github.com/sirupsen/logrus v1.9.3/go.mod h1:naHLuLoDiP4jHNo9R0sCBMtWGeIprob74mVsIT4qYEQ=
github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
github.com/stretchr/testify v1.7.0/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
github.com/stretchr/testify v1.8.4 h1:CcVxjf3Q8PM0mHUKJCdn+eZZtm5yQwehR5yeSVQQcUk=
github.com/stretchr/testify v1.8.4/go.mod h1:sz/lmYIOXD/1dqDmKjjqLyZ2RngseejIcXlSw2iwfAo=
go.opentelemetry.io/otel v1.19.0 h1:MuS/TNf4/j4IXsZuJegVzI1cwut7Qc00344rgH7p8bs=
go.opentelemetry.io/otel v1.19.0/go.mod h1:i0QyjOq3UPoTzff0PJB2N66fb4S0+rSbSB15/oyH9fY=
go.opentelemetry.io/otel/metric v1.19.0 h1:aTzpGtV0ar9wlV4Sna9sdJyII5jTVJEvKETPiOKwvpE=
go.opentelemetry.io/otel/metric v1.19.0/go.mod h1:L5rUsV9kM1IxCj1MmSdS+JQAcVm319EUrDVLrt7jqt8=
go.opentelemetry.io/otel/trace v1.19.0 h1:DFVQmlVbfVeOuBRrwdtaehRrWiL1JoVs9CPIQ1Dzxpg=
go.opentelemetry.io/otel/trace v1.19.0/go.mod h1:mfaSyvGyEJEI0nyV2I4qhNQnbBOUUmYZpYojqMnX2vo=
golang.org/x/net v0.16.0 h1:7eBu7KsSvFDtSXUIDbh3aqlK4DPsZ1rByC8PFfBThos=
golang.org/x/net v0.16.0/go.mod h1:NxSsAGuq816PNPmqtQdLE42eU2Fs7NoRIZrHJAlaCOE=
golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.13.0 h1:Af8nKPmuFypiUBjVoU9V20FiaFXOcuZI21p0ycVYYGE=
golang.org/x/sys v0.13.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/text v0.13.0 h1:ablQoSUd0tRdKxZewP80B+BaqeKJuVhuRxj/dkrun3k=
golang.org/x/text v0.13.0/go.mod h1:TvPlkZtksWOMsz7fbANvkp4WM8x/WCo/om8BMLbz+aE=
golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=
google.golang.org/genproto/googleapis/rpc v0.0.0-20230711160842-782d3b101e98 h1:bVf09lpb+OJbByTj913DRJioFFAjf/ZGxEz7MajTp2U=
google.golang.org/genproto/googleapis/rpc v0.0.0-20230711160842-782d3b101e98/go.mod h1:TUfxEVdsvPg18p6AslUXFoLdpED4oBnGwyqk3dV1XzM=
google.golang.org/grpc v1.58.2 h1:SXUpjxeVF3FKrTYQI4f4KvbGD5u2xccdYdurwowix5I=
google.golang.org/grpc v1.58.2/go.mod h1:tgX3ZQDlNJGU96V6yHh1T/JeoBQ2TXdr43YbYSsCJk0=
google.golang.org/protobuf v1.26.0-rc.1/go.mod h1:jlhhOSvTdKEhbULTjvd4ARK9grFBp09yW+WbY/TyQbw=
google.golang.org/protobuf v1.26.0/go.mod h1:9q0QmTI4eRPtz6boOQmLYwt+qCgq0jsYwAQnmE0givc=
google.golang.org/protobuf v1.31.0 h1:g0LDEJHgrBl9N9r17Ru3sqWhkIx2NB67okBHPwC7hs8=
google.golang.org/protobuf v1.31.0/go.mod h1:HV8QOd/L58Z+nl8r43ehVNZIU/HEI6OcFqwMG9pJV4I=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
"""
    go_workflow = """name: Build and Verify
on:
  push:
    branches: [ "main", "agent/*" ]
  pull_request:
    branches: [ "main" ]

jobs:
  build:
    name: Build & Verify Lockfile
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
      - name: Setup Go Environment
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'
          cache: true
      - name: Verify go.sum Lockfile Authenticity
        run: go mod verify
      - name: Build Microservice Binary
        run: go build -v ./...
      - name: Run Unit Tests
        run: go test -v ./...
"""
    create_or_update_file("frontend", "go.mod", frontend_mod, "Initial go.mod with baseline dependencies")
    create_or_update_file("frontend", "main.go", frontend_main, "Add frontend web server implementation")
    create_or_update_file("frontend", "go.sum", frontend_sum, "Add authentic go.sum lockfile")
    create_or_update_file("frontend", ".gitea/workflows/build.yaml", go_workflow, "Add Gitea Actions build & verification workflow")

    # 2. Payments (Go service with vulnerable golang.org/x/crypto v0.14.0 - CVE-2023-48795 Terrapin)
    print("\n[2/4] Populating online-boutique/payments (Go)...")
    payments_mod = """module github.com/GoogleCloudPlatform/microservices-demo/src/paymentservice

go 1.21

require (
	github.com/google/uuid v1.3.1
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/crypto v0.14.0 // CVE-2023-48795 (Terrapin Prefix Truncation)
	google.golang.org/grpc v1.58.2
)
"""
    payments_main = """package main

import (
	"fmt"
	"net"
	"github.com/sirupsen/logrus"
	_ "golang.org/x/crypto/ssh"
	_ "google.golang.org/grpc"
	_ "github.com/google/uuid"
)

func main() {
	logrus.Info("Payment service listening on port 50051")
	l, err := net.Listen("tcp", ":50051")
	if err != nil {
		logrus.Fatalf("Failed to listen: %v", err)
	}
	defer l.Close()
	fmt.Println("Payment service ready")
}
"""
    payments_sum = """github.com/davecgh/go-spew v1.1.0/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/golang/protobuf v1.5.0/go.mod h1:FsONVRAS9T7sI+LIUmWTfcYkHO4aIWwzhcaSAoJOfIk=
github.com/golang/protobuf v1.5.3 h1:KhyjKVUg7Usr/dYsdSqoFveMYd5ko72D+zANwlG1mmg=
github.com/golang/protobuf v1.5.3/go.mod h1:XVQd3VNwM+JqD3oG2Ue2ip4fOMUkwXdXDdiuN0vRsmY=
github.com/google/go-cmp v0.5.5/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/go-cmp v0.5.9 h1:O2Tfq5qg4qc4AmwVlvv0oLiVAGB7enBSJ2x2DqQFi38=
github.com/google/go-cmp v0.5.9/go.mod h1:17dUlkBOakJ0+DkrSSNjCkIjxS6bF9zb3elmeNGIjoY=
github.com/google/uuid v1.3.1 h1:KjJaJ9iWZ3jOFZIf1Lqf4laDRCasjl0BCmnEGxkdLb4=
github.com/google/uuid v1.3.1/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/sirupsen/logrus v1.9.3 h1:dueUQJ1C2q9oE3F7wvmSGAaVtTmUizReu6fjN8uqzbQ=
github.com/sirupsen/logrus v1.9.3/go.mod h1:naHLuLoDiP4jHNo9R0sCBMtWGeIprob74mVsIT4qYEQ=
github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
github.com/stretchr/testify v1.7.0 h1:nwc3DEeHmmLAfoZucVR881uASk0Mfjw8xYJ99tb5CcY=
github.com/stretchr/testify v1.7.0/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
golang.org/x/crypto v0.14.0 h1:wBqGXzWJW6m1XrIKlAH0Hs1JJ7+9KBwnIO8v66Q9cHc=
golang.org/x/crypto v0.14.0/go.mod h1:MVFd36DqK4CsrnJYDkBA3VC4m2GkXAM0PvzMCn4JQf4=
golang.org/x/net v0.12.0 h1:cfawfvKITfUsFCeJIHJrbSxpeu/E81khclypR0GVT50=
golang.org/x/net v0.12.0/go.mod h1:zEVYFnQC7m/vmpQFELhcD1EWkZlX69l4oqgmer6hfKA=
golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.13.0 h1:Af8nKPmuFypiUBjVoU9V20FiaFXOcuZI21p0ycVYYGE=
golang.org/x/sys v0.13.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/term v0.13.0 h1:bb+I9cTfFazGW51MZqBVmZy7+JEJMouUHTUSKVQLBek=
golang.org/x/term v0.13.0/go.mod h1:LTmsnFJwVN6bCy1rVCoS+qHT1HhALEFxKncY3WNNh4U=
golang.org/x/text v0.13.0 h1:ablQoSUd0tRdKxZewP80B+BaqeKJuVhuRxj/dkrun3k=
golang.org/x/text v0.13.0/go.mod h1:TvPlkZtksWOMsz7fbANvkp4WM8x/WCo/om8BMLbz+aE=
golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=
google.golang.org/genproto/googleapis/rpc v0.0.0-20230711160842-782d3b101e98 h1:bVf09lpb+OJbByTj913DRJioFFAjf/ZGxEz7MajTp2U=
google.golang.org/genproto/googleapis/rpc v0.0.0-20230711160842-782d3b101e98/go.mod h1:TUfxEVdsvPg18p6AslUXFoLdpED4oBnGwyqk3dV1XzM=
google.golang.org/grpc v1.58.2 h1:SXUpjxeVF3FKrTYQI4f4KvbGD5u2xccdYdurwowix5I=
google.golang.org/grpc v1.58.2/go.mod h1:tgX3ZQDlNJGU96V6yHh1T/JeoBQ2TXdr43YbYSsCJk0=
google.golang.org/protobuf v1.26.0-rc.1/go.mod h1:jlhhOSvTdKEhbULTjvd4ARK9grFBp09yW+WbY/TyQbw=
google.golang.org/protobuf v1.26.0/go.mod h1:9q0QmTI4eRPtz6boOQmLYwt+qCgq0jsYwAQnmE0givc=
google.golang.org/protobuf v1.31.0 h1:g0LDEJHgrBl9N9r17Ru3sqWhkIx2NB67okBHPwC7hs8=
google.golang.org/protobuf v1.31.0/go.mod h1:HV8QOd/L58Z+nl8r43ehVNZIU/HEI6OcFqwMG9pJV4I=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c h1:dUUwHk2QECo/6vqA44rthZ8ie2QXMNeKRTHCNY2nXvo=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
"""
    create_or_update_file("payments", "go.mod", payments_mod, "Initial go.mod for paymentservice")
    create_or_update_file("payments", "main.go", payments_main, "Payment service entry point")
    create_or_update_file("payments", "go.sum", payments_sum, "Add authentic go.sum lockfile")
    create_or_update_file("payments", ".gitea/workflows/build.yaml", go_workflow, "Add Gitea Actions build & verification workflow")

    # 3. Recommendations (Python service with vulnerable urllib3 1.26.17 - CVE-2023-43804 & CVE-2023-45803)
    print("\n[3/4] Populating online-boutique/recommendations (Python)...")
    rec_reqs = """# Online Boutique Recommendations Service Dependencies
urllib3==1.26.17 # CVE-2023-43804 (Cookie leak), CVE-2023-45803 (Request body leak)
requests==2.31.0
grpcio==1.58.0
protobuf==4.24.3
"""
    rec_py = """# Recommendations Service
import urllib3
import requests

def get_recommendations(user_id):
    http = urllib3.PoolManager()
    return ["product-001", "product-002", "product-003"]

if __name__ == "__main__":
    print("Recommendations service initialized")
"""
    py_workflow = """name: Build and Test
on:
  push:
    branches: [ "main", "agent/*" ]
  pull_request:
    branches: [ "main" ]

jobs:
  test:
    name: Lint & Test
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Verify Requirements Syntax
        run: python -m py_compile recommendation_server.py
"""
    create_or_update_file("recommendations", "requirements.txt", rec_reqs, "Initial requirements.txt with known CVEs")
    create_or_update_file("recommendations", "recommendation_server.py", rec_py, "Recommendation service implementation")
    create_or_update_file("recommendations", ".gitea/workflows/build.yaml", py_workflow, "Add Gitea Actions test workflow")

    # 4. Platform (Go Kubernetes manifests and controller)
    print("\n[4/4] Populating online-boutique/platform (Go / K8s)...")
    platform_mod = """module github.com/GoogleCloudPlatform/microservices-demo/src/platform

go 1.21

require (
	k8s.io/client-go v0.28.2
	k8s.io/apimachinery v0.28.2
)
"""
    k8s_frontend = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  labels:
    app: frontend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: server
        image: gcr.io/google-samples/microservices-demo/frontend:v0.8.0
        ports:
        - containerPort: 8080
"""
    create_or_update_file("platform", "go.mod", platform_mod, "Initial platform go.mod")
    create_or_update_file("platform", "k8s/frontend-deployment.yaml", k8s_frontend, "Add frontend deployment manifest")
    create_or_update_file("platform", ".gitea/workflows/build.yaml", go_workflow, "Add Gitea Actions build & verification workflow")

    print("\n============================================================")
    print("Seeding complete! All 4 synthetic microservices populated.")
    print("============================================================")

if __name__ == "__main__":
    main()
