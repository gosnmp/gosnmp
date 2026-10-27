all: test lint

.PHONY: test
test:
	go test ./...
	go test -v -tags helper
	go test -v -tags marshal
	go test -v -tags misc
	go test -v -tags api
	go test -v -tags end2end
	go test -v -tags trap
	$(MAKE) -C netsnmp test

.PHONY: test-race
test-race:
	go test -v -tags all -race

.PHONY: net-snmp-test
net-snmp-test:
	$(MAKE) -C netsnmp test_netsnmp

.PHONY: lint
lint: check_license

.PHONY: check_license
check_license:
	@echo ">> checking license header"
	@licRes=$$(for file in $$(find . -type f -iname '*.go' ! -path './vendor/*') ; do \
               awk 'NR<=3' $$file | grep -Eq "(Copyright [0-9]+ The GoSNMP Authors|generated|GENERATED)" || echo $$file; \
       done); \
       if [ -n "$${licRes}" ]; then \
               echo "license header checking failed:"; echo "$${licRes}"; \
               exit 1; \
       fi

.PHONY: generate
generate:
	@echo ">> Installing tools"
	@go install golang.org/x/tools/cmd/stringer@latest
	@go install github.com/golang/mock/mockgen@latest
	@echo ">> Generating code"
	go generate
