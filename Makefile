# PANDA Docker — development targets.
#
# The point of `dev-env` and `dev-certs` is that going from a clone to a
# running service should not require reading documentation about key
# generation. Anything that takes more than two minutes gets skipped.

IMAGE ?= panda-docker:local
VERSION ?= 0.1.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

.PHONY: help build test vet fmt image run-dev run-grpc dev-env dev-certs clean smoke

help:
	@echo "build      compile the service"
	@echo "test       run the test suite"
	@echo "image      build the container image"
	@echo "dev-env    write .env with a throwaway key"
	@echo "dev-certs  write a throwaway CA, server cert, and client cert"
	@echo "run-dev    start the dev compose stack"
	@echo "run-grpc   start it on the gRPC transport instead"
	@echo "smoke      run the container smoke test"

build:
	go build -o panda-docker ./cmd/panda-docker

test:
	go test -race ./...

vet:
	gofmt -l . | tee /dev/stderr | wc -l | grep -q '^0$$'
	go vet ./...

fmt:
	gofmt -w .

image:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE) .

# Generates a throwaway key for local development.
#
# Regenerating this invalidates every value encrypted under the previous key,
# which is the correct behaviour — and the reason it prints a warning rather
# than doing it silently.
dev-env:
	@if [ -f .env ] && [ -z "$$FORCE" ]; then \
		echo ".env exists. Re-run with FORCE=1 to regenerate, which will make"; \
		echo "every value encrypted under the old key unreadable."; \
		exit 1; \
	fi
	@printf 'PANDA_IMAGE=%s\n' "$(IMAGE)" > .env
	@printf 'PANDA_KEY_DEV_KEY=%s\n' "$$(head -c 32 /dev/urandom | base64)" >> .env
	@printf 'PANDA_INDEX_KEY=%s\n' "$$(head -c 32 /dev/urandom | base64)" >> .env
	@echo "wrote .env with a throwaway development key"

# A self-signed CA, a server certificate, and one client certificate.
#
# Throwaway. The client certificate is what makes mTLS testable locally —
# without one, there is no way to exercise the production auth mode short of
# standing up a real CA.
dev-certs:
	@mkdir -p certs
	@openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
		-keyout certs/client-ca.key -out certs/client-ca.crt \
		-subj "/CN=panda-dev-client-ca" 2>/dev/null
	@openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
		-keyout certs/tls.key -out certs/tls.crt \
		-subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
	@openssl req -newkey rsa:2048 -nodes \
		-keyout certs/client.key -out certs/client.csr \
		-subj "/CN=panda-dev-client" 2>/dev/null
	@openssl x509 -req -in certs/client.csr -CA certs/client-ca.crt \
		-CAkey certs/client-ca.key -CAcreateserial -days 30 \
		-out certs/client.crt 2>/dev/null
	@rm -f certs/client.csr certs/client-ca.srl
	@echo "wrote certs/ — throwaway material, do not deploy it"

run-dev:
	docker compose -f docker-compose.dev.yml up

run-grpc:
	docker compose -f docker-compose.dev.yml -f docker-compose.grpc.yml up

smoke:
	bash scripts/smoke.sh $(IMAGE)

clean:
	rm -rf certs .env panda-docker
