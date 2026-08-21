// Command mockbackend is a throwaway tenant "microservice" for exercising
// the gateway's reverse proxy locally: it echoes back the request path and
// every X-B2BFP-* header the gateway injected after authn/ABAC, so you can
// see exactly what identity/authz context the backend would receive.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"
)

func main() {
	addr := flag.String("addr", ":9090", "listen address")
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := map[string]string{"path": r.URL.Path, "method": r.Method}
		for k, v := range r.Header {
			if strings.HasPrefix(k, "X-B2bfp-") || strings.HasPrefix(k, "X-B2BFP-") {
				ctx[k] = strings.Join(v, ",")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ctx)
	})
	log.Printf("mockbackend listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
