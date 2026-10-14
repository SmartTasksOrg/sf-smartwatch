// Command interop is the Go program for ports/conformance/interop.py (spec/PORTING.md, "The interop
// program"):
//
//	interop URL AGENT_IDS SECONDS
//
// with the ingest token in SMARTWATCH_INGEST_TOKEN. It starts the reporter and one command poller per
// agent (200 ms), prints "RESET <agent> <reset_id>" for every command, records every ordered pair once
// per 100 ms round for SECONDS × 10 rounds, closes the reporter and prints "SENT <accepted>", then keeps
// polling until standard input closes.
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	sw "github.com/SmartTasksOrg/sf-smartwatch/ports/go/smartwatch"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: interop URL AGENT_IDS SECONDS")
		os.Exit(2)
	}
	url, ids := os.Args[1], strings.Split(os.Args[2], ",")
	seconds, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	token := os.Getenv("SMARTWATCH_INGEST_TOKEN")
	var out sync.Mutex
	println := func(s string) {
		out.Lock()
		defer out.Unlock()
		fmt.Fprintln(os.Stdout, s) // os.Stdout is unbuffered
	}
	var pollers []*sw.CommandPoller
	for _, a := range ids {
		a := a
		c, err := sw.NewClient(url, token, 5*time.Second)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		p := sw.NewCommandPoller(c, a, func(cmd sw.Command) error {
			println(fmt.Sprintf("RESET %s %v", a, cmd["reset_id"]))
			return nil
		}, 200*time.Millisecond)
		p.OnError = func(err error) { fmt.Fprintf(os.Stderr, "polling %s failed: %v\n", a, err) }
		pollers = append(pollers, p.Start())
	}
	c, err := sw.NewClient(url, token, 5*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	rep := sw.NewReporter(c).Start()
	t0 := time.Now()
	for r := 0; r < seconds*10; r++ {
		for _, a := range ids {
			for _, b := range ids {
				if a != b {
					if err := rep.Record(a, b, 1); err != nil {
						fmt.Fprintln(os.Stderr, err)
					}
				}
			}
		}
		time.Sleep(time.Until(t0.Add(time.Duration(r+1) * 100 * time.Millisecond)))
	}
	rep.Close()
	st := rep.Stats()
	if st.LastError != nil {
		fmt.Fprintf(os.Stderr, "reporter: last error %v\n", st.LastError)
	}
	println(fmt.Sprintf("SENT %d", st.Sent))
	_, _ = io.Copy(io.Discard, os.Stdin)
	for _, p := range pollers {
		p.Stop()
	}
}
