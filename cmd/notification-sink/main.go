// Command notification-sink is a development webhook receiver: it prints
// every request certel delivers so the alerting pipeline can be tested
// end to end without a real endpoint.
//
//	go run ./cmd/notification-sink              # listen on :9999, respond 200
//	go run ./cmd/notification-sink -status 500  # simulate a broken endpoint
//	go run ./cmd/notification-sink -verbose     # also print request headers
//
// The default port matches the placeholder alert.url in config.example.yaml,
// so "run the sink, run the monitor" is enough to see alerts flowing.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

func main() {
	listen := flag.String("listen", ":9999", "address to listen on")
	status := flag.Int("status", http.StatusOK, "HTTP status to respond with")
	verbose := flag.Bool("verbose", false, "print request headers too")
	flag.Parse()

	var count atomic.Int64
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			log.Printf("reading body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := count.Add(1)
		fmt.Printf("--- #%d %s %s %s\n", n, time.Now().Format("15:04:05"), r.Method, r.URL.Path)
		if *verbose {
			for k, vals := range r.Header {
				for _, v := range vals {
					fmt.Printf("%s: %s\n", k, v)
				}
			}
			fmt.Println()
		}
		// Alerts are normally JSON; pretty-print them, pass anything else
		// through as-is.
		var pretty bytes.Buffer
		if json.Indent(&pretty, body, "", "  ") == nil {
			fmt.Println(pretty.String())
		} else {
			fmt.Println(string(body))
		}
		w.WriteHeader(*status)
	})

	log.Printf("notification-sink listening on %s, responding %d to every request", *listen, *status)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
