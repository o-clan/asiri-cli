package broker

import "fmt"

type OnceSummary struct {
	Address string
	Mode    string
	Policy  string
}

func StartOnce() OnceSummary {
	return OnceSummary{Address: "127.0.0.1:0", Mode: "loopback-smoke", Policy: "client token + explicit grants required"}
}

func (s OnceSummary) String() string {
	return fmt.Sprintf("asiri broker ready (%s, %s)", s.Mode, s.Policy)
}
