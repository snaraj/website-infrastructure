package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

func main() {
	if strings.EqualFold(os.Getenv("FAIL_STARTUP"), "true") {
		os.Exit(42)
	}
	http.HandleFunc("/ready", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(response, "ready")
	})
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
