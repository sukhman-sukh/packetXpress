// simplebackend — minimal HTTP/1.1 server for gateway demo backends.
//
//	go run ./cmd/simplebackend -listen 0.0.0.0:8081 -id node-a
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:8080", "TCP listen address (host:port)")
	id := flag.String("id", "", "backend id (required, echoed in JSON)")
	flag.Parse()

	if *id == "" {
		flag.Usage()
		log.Fatal("-id is required (e.g. -id backend-a)")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend-ID", *id)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"backend": *id,
			"host":    r.Host,
			"path":    r.URL.Path,
		})
	})

	log.Printf("simplebackend id=%q listening on %s", *id, *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatal(err)
	}
}
