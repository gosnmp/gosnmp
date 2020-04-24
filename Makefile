.PHONY: test lint  lintall tools

test:
	go test *.go

lint: # lint all commits going forwards
	golangci-lint run --new-from-rev bf84454 -p bugs -p complexity -p unused -p format -E lll -E interfacer *.go

lintall: # lint all commits - ugh...
	golangci-lint run -p bugs -p complexity -p unused -p format -E lll -E interfacer *.go

tools: # install build tools
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.24.0
