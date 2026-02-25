all: target/trigger target/catch

target/catch: target
	gcc catch/filter.c catch/main.c -o target/catch

target/trigger: target
	go build -o target/trigger ./trigger/main.go

target:
	mkdir -p target

clean:
	rm -rf target
