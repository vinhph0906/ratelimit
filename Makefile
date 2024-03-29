build:
	go build --race -o ratelimit cmd/server/server.go

run:
	go run cmd/server/server.go --rules-file=./env/rules.yaml

docker-build:
	docker build -t localhost:32000/r8limiter:0.2 .

docker-push:
	docker push localhost:32000/r8limiter:0.2

pprof:
	go tool pprof -http=localhost:8444 http://localhost:8082/debug/pprof/profile