package abac

import "time"

// BusinessHours is a weekly recurring window, evaluated in a fixed IANA
// timezone so "business hours" means the same wall-clock thing regardless
// of where the gateway process happens to run.
type BusinessHours struct {
	Timezone  string `json:"timezone"`
	Days      []int  `json:"days"` // 0=Sunday..6=Saturday
	StartHour int    `json:"start_hour"`
	EndHour   int    `json:"end_hour"`
}

// Environment holds the named values policies refer to symbolically
// (`request.Source_IP matches Vpc_Range`, `time.Now() is Business_Hours`)
// instead of embedding literals in every policy.
type Environment struct {
	CIDRRanges    map[string]string `json:"cidr_ranges"`
	BusinessHours BusinessHours     `json:"business_hours"`
}

// Context is everything a single access decision is evaluated against.
// Time is explicit (not read from the wall clock inside the evaluator) so
// evaluation stays deterministic and unit-testable: the same Context always
// produces the same Decision.
type Context struct {
	User        map[string]any
	Request     map[string]any
	Resource    map[string]any
	Time        time.Time
	Environment Environment
}

func NewContext(user, request map[string]any, now time.Time, env Environment) *Context {
	if user == nil {
		user = map[string]any{}
	}
	if request == nil {
		request = map[string]any{}
	}
	return &Context{User: user, Request: request, Resource: map[string]any{}, Time: now, Environment: env}
}
