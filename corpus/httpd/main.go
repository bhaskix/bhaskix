// SPDX-License-Identifier: Apache-2.0

// The motivating workload -- RFC 0086: a plain net/http server, statically
// linked, run in a Linux-tagged domain and loaded by the host through QEMU's
// port forward.
//
// The body is derived from the request's path, so a response delivered to the
// wrong request is a wrong body rather than a plausible one. "httpd listening"
// is printed only once the socket listens, which is what the harness waits for
// before it starts the load.
//
// **And it dials out** -- RFC 0090 step 8. Once it listens it dials the echo
// peer QEMU's guestfwd runs at 10.0.2.100:9 and checks its bytes come back,
// then dials 10.0.2.100:10, which no guestfwd names, and checks Go reports the
// refusal as ECONNREFUSED. In a goroutine, so the server is taking the
// harness's clients while it does: a dial has to get a ring pair while the
// listener holds its own. The kernel grants this domain the network because
// this program dials; an ungranted one is told EACCES.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
)

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("httpd failed to listen:", err)
		os.Exit(1)
	}
	fmt.Println("httpd listening")
	go dial()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "bhaskix %s\n", r.URL.Path)
	})
	if err := http.Serve(listener, handler); err != nil {
		fmt.Println("httpd stopped:", err)
		os.Exit(1)
	}
}

// dial is RFC 0090 step 8's client. net.Dial with no deadline, which is the
// path read from Go 1.27.1's source: connect answers EINPROGRESS, the
// netpoller waits for the socket to be writable, then SO_ERROR, and then
// getpeername, which must succeed or Go waits for another edge rather than
// reconnecting.
func dial() {
	message := []byte("bhaskix-go-dials")
	conn, err := net.Dial("tcp", "10.0.2.100:9")
	if err != nil {
		fmt.Println("httpd dial FAILED:", err)
		return
	}
	back := make([]byte, len(message))
	_, err = conn.Write(message)
	if err == nil {
		_, err = io.ReadFull(conn, back)
	}
	conn.Close()
	switch {
	case err != nil:
		fmt.Println("httpd dial FAILED: the echo:", err)
		return
	case !bytes.Equal(back, message):
		fmt.Printf("httpd dial FAILED: %q came back for %q\n", back, message)
		return
	}
	fmt.Printf("httpd dial ok: %s -> %s, %d bytes echoed\n", conn.LocalAddr(), conn.RemoteAddr(), len(back))

	refused, err := net.Dial("tcp", "10.0.2.100:10")
	if err == nil {
		refused.Close()
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		fmt.Println("httpd dial refused ok:", err)
	} else {
		fmt.Println("httpd dial FAILED: 10.0.2.100:10 is refused by every boot, and the dial answered", err)
	}
}
