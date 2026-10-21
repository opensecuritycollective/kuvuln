module github.com/example/demo

go 1.22

toolchain go1.25.0

require (
	github.com/gorilla/mux v1.8.0
	golang.org/x/text v0.3.0
)

require (
	github.com/pkg/errors v0.9.1 // indirect
)

replace golang.org/x/text => github.com/example/text-fork v0.4.0
