# Build and run the test container, then execute e2e tests.
#
#   make container  — build the net-snmp Docker image
#   make test       — run e2e tests (requires GOSNMP_TARGET / GOSNMP_PORT)
#   make run        — build container, start it, run tests, stop it

IMAGE := gosnmp-e2e
CONTAINER := gosnmp-e2e

.PHONY: container test run stop

container:
	docker build -t $(IMAGE) testcontainer/

test:
	go test -v -count=1 ./...

run: container stop
	docker run -d --name $(CONTAINER) -p 1161:161/udp -p 1161:161/tcp $(IMAGE)
	@echo "Waiting for snmpd..."
	@for i in $$(seq 1 50); do \
		docker logs $(CONTAINER) 2>&1 | grep -q SNMPD_READY && break; \
		sleep 0.1; \
	done
	GOSNMP_TARGET=127.0.0.1 GOSNMP_PORT=1161 go test -v -count=1 ./...
	docker stop $(CONTAINER) && docker rm $(CONTAINER)

stop:
	-docker stop $(CONTAINER) 2>/dev/null && docker rm $(CONTAINER) 2>/dev/null || true
