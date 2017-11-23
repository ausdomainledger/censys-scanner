// LICENCE: No licence is provided for this project

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

const (
	maxRetries    = 360
	retryInterval = time.Minute
)

var (
	db       *sqlx.DB
	cl       *http.Client
	throttle *rate.Limiter
)

func main() {
	var err error
	db, err = sqlx.Open("postgres", os.Getenv("SCANNER_DSN"))
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	cl = &http.Client{
		Timeout: 30 * time.Minute,
		Transport: &http.Transport{
			ResponseHeaderTimeout: 60 * time.Second,
			DisableKeepAlives:     false,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
		},
	}

	throttle = rate.NewLimiter(rate.Limit(0.4), 1)

	for {
		crawl()

		time.Sleep(time.Hour)
	}

}

func crawl() {
	/*
		curl -X POST --data '{"query":"parsed.names:au tags:trusted","fields":["parsed.names","parsed.validity.start"]}' -u "f6b91878-b560-413a-9cc8-ab32e5b31c5d:rwa5QbmlXkBcHtwKYyCEyjrE5NaWAZxw" https://www.censys.io/api/v1/search/certificates
	*/
	var buf bytes.Buffer
	ctx := context.Background()

	page := uint64(1)
	for {

		var res struct {
			Results []struct {
				Names    []string  `json:"parsed.names"`
				Validity time.Time `json:"parsed.validity.start"`
			} `json:"results"`
			Meta struct {
				Pages uint64 `json:"pages"`
			} `json:"metadata"`
			Status string `json:"status"`
		}

		names := map[string]int64{}

		for attempt := 0; attempt < maxRetries; attempt++ {
			buf.Reset()

			if err := json.NewEncoder(&buf).Encode(map[string]interface{}{
				"query":  "parsed.names:au tags:trusted",
				"fields": []string{"parsed.names", "parsed.validity.start"},
				"page":   page,
			}); err != nil {
				panic(err)
			}

			r, _ := http.NewRequest("POST", "https://www.censys.io/api/v1/search/certificates", &buf)
			r.SetBasicAuth(os.Getenv("SCANNER_CENSYS_USER"), os.Getenv("CENSYS_SCANNER_PASSWORD"))

			throttle.Wait(ctx)

			resp, err := cl.Do(r)
			if err != nil || resp.StatusCode != 200 {
				log.Printf("Fetch failed for %s (attempt %d, page %d, body %v): %v", r.URL.String(), attempt, page, buf.String(), err)
				if resp != nil {
					log.Printf("Status code: %d", resp.StatusCode)
				}
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
				time.Sleep(retryInterval)
				continue
			}

			if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
				log.Printf("Unmarshal failed: %v", res)
				resp.Body.Close()
			}

			break
		}

		if res.Status != "ok" {
			log.Printf("Res status not OK so we do nothing")
		} else {
			for _, entry := range res.Results {
				for _, name := range entry.Names {
					name = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(name, ".")))
					if strings.HasSuffix(name, ".au") {
						names[name] = entry.Validity.Unix()
					}
				}
			}

			submitNames(names)
		}

		page++

		if page >= res.Meta.Pages {
			log.Println("Reached end")
			page = 1
		}
	}

}

func submitNames(domains map[string]int64) {
	for name, ts := range domains {
		etld, err := publicsuffix.EffectiveTLDPlusOne(name)
		if err != nil {
			log.Printf("Couldn't determine etld for %s: %v", name, err)
		}

		if _, err := db.Exec(`INSERT INTO domains (domain, first_seen, last_seen, etld) VALUES ($1, $2, $2, $3) ON CONFLICT (domain) DO UPDATE SET last_seen = GREATEST($2,domains.first_seen), first_seen = LEAST(domains.first_seen, $2);`, name, ts, etld); err != nil {
			log.Printf("Failed to insert/update %s: %v", name, err)
		}
	}
}
