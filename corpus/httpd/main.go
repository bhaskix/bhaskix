// SPDX-License-Identifier: Apache-2.0

// The motivating workload -- RFC 0086: a plain net/http server, statically
// linked, run in a Linux-tagged domain and loaded by the host through QEMU's
// port forward.
//
// The body is derived from the request's path, so a response delivered to the
// wrong request is a wrong body rather than a plausible one. "httpd listening"
// is printed only once the socket listens, which is what the harness waits for
// before it starts the load.
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
)

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("httpd failed to listen:", err)
		os.Exit(1)
	}
	fmt.Println("httpd listening")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "bhaskix %s\n", r.URL.Path)
	})
	if err := http.Serve(listener, handler); err != nil {
		fmt.Println("httpd stopped:", err)
		os.Exit(1)
	}
}
