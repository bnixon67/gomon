package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/bnixon67/gomon"
)

func main() {
	urls := []string{
		"https://bn67.net",
		"https://expired.badssl.com/",
		"https://wrong.host.badssl.com/",
		"http://example.com",
	}
	method := http.MethodGet

	// Pre-allocate slice and populate directly
	monitors := make([]*gomon.Monitor, len(urls))
	for i, url := range urls {
		var err error
		monitors[i], err = gomon.NewMonitor(
			gomon.Config{
				URL:            url,
				Method:         method,
				RequestTimeout: 10 * time.Second,
				IgnoreCert:     true,
				//DontFollowRedirect: true,
			})
		if err != nil {
			fmt.Println(err)
		}
	}

	var wg sync.WaitGroup
	for _, m := range monitors {
		if m != nil {
			wg.Add(1)
			go func(m *gomon.Monitor) {
				defer wg.Done()
				result, err := m.Check(context.Background())
				if err != nil {
					fmt.Println(err)
					return
				}
				fmt.Println(result)
			}(m)
		}
	}

	wg.Wait()
}
