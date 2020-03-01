build:
	go build -o ./bin/auth ./serve/

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/auth_amd64 ./serve/

docker-build: build-linux
	docker build -t "pravahio/auth:latest" .