package rules

import "testing"

func TestCompileOutcallAction_SocketAndURLMutuallyExclusive(t *testing.T) {
	cases := []struct {
		name    string
		params  Params
		wantErr bool
	}{
		{"socket only", Params{"socket": "/run/broker.sock"}, false},
		{"url only", Params{"url": "https://broker.example/decide"}, false},
		{"neither", Params{}, true},
		{"both", Params{"socket": "/run/broker.sock", "url": "https://broker.example/decide"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileOutcallAction(Action{Action: "webhook", Params: tc.params})
			if (err != nil) != tc.wantErr {
				t.Fatalf("compileOutcallAction(%+v): err=%v, wantErr=%v", tc.params, err, tc.wantErr)
			}
		})
	}
}

func TestCompileOutcallAction_PathDefaultsAndRejectsWithoutSocket(t *testing.T) {
	co, err := compileOutcallAction(Action{Action: "webhook", Params: Params{"socket": "/run/broker.sock"}})
	if err != nil {
		t.Fatalf("compileOutcallAction: %v", err)
	}
	if co.Path != "/" {
		t.Fatalf("Path = %q, want \"/\" default", co.Path)
	}

	if _, err := compileOutcallAction(Action{Action: "webhook", Params: Params{"url": "https://broker.example/", "path": "/x"}}); err == nil {
		t.Fatalf("expected error: \"path\" alongside \"url\" (path only applies to socket)")
	}
}

func TestCompileOutcallAction_SendCanonicalizesHeaderNames(t *testing.T) {
	co, err := compileOutcallAction(Action{
		Action: "webhook",
		Params: Params{"socket": "/run/broker.sock", "send": []any{"user-agent", "ACCEPT"}},
	})
	if err != nil {
		t.Fatalf("compileOutcallAction: %v", err)
	}
	want := []string{"User-Agent", "Accept"}
	if len(co.Send) != len(want) || co.Send[0] != want[0] || co.Send[1] != want[1] {
		t.Fatalf("Send = %v, want %v", co.Send, want)
	}
}

func TestCompileOutcallAction_FailOpenDefaultsFalse(t *testing.T) {
	co, err := compileOutcallAction(Action{Action: "webhook", Params: Params{"socket": "/run/broker.sock"}})
	if err != nil {
		t.Fatalf("compileOutcallAction: %v", err)
	}
	if co.FailOpen {
		t.Fatalf("FailOpen = true, want false default")
	}

	co2, err := compileOutcallAction(Action{Action: "webhook", Params: Params{"socket": "/run/broker.sock", "failOpen": true}})
	if err != nil {
		t.Fatalf("compileOutcallAction: %v", err)
	}
	if !co2.FailOpen {
		t.Fatalf("FailOpen = false, want true")
	}
}

func TestCompileOutcallAction_CacheKeyStableAndParamSensitive(t *testing.T) {
	a := Action{Action: "webhook", Params: Params{"socket": "/run/broker.sock", "send": []any{"Accept"}}}
	co1, err := compileOutcallAction(a)
	if err != nil {
		t.Fatalf("compileOutcallAction: %v", err)
	}
	co2, err := compileOutcallAction(a)
	if err != nil {
		t.Fatalf("compileOutcallAction: %v", err)
	}
	if co1.CacheKey != co2.CacheKey {
		t.Fatalf("CacheKey not stable across identical compiles: %q vs %q", co1.CacheKey, co2.CacheKey)
	}

	diff := Action{Action: "webhook", Params: Params{"socket": "/run/broker.sock", "send": []any{"Accept", "User-Agent"}}}
	co3, err := compileOutcallAction(diff)
	if err != nil {
		t.Fatalf("compileOutcallAction: %v", err)
	}
	if co1.CacheKey == co3.CacheKey {
		t.Fatalf("CacheKey did not change when params changed — a rule edit would not invalidate its own cache entries")
	}
}

func TestCompile_WebhookAndHeaderFetchAreValidRequestActions(t *testing.T) {
	doc := `{"http":[{"match":{},
	  "request":[
	    {"action":"webhook","params":{"socket":"/run/approve.sock","path":"/decide"}},
	    {"action":"header.fetch","params":{"socket":"/run/broker.sock","path":"/creds/example"}}
	  ]}]}`
	compiled := mustCompile(t, doc)
	if len(compiled) != 1 || len(compiled[0].request) != 2 {
		t.Fatalf("compiled = %+v", compiled)
	}
	if compiled[0].request[0].Outcall == nil || compiled[0].request[1].Outcall == nil {
		t.Fatalf("Outcall not populated on webhook/header.fetch actions")
	}
}

func TestCompile_OutcallInResponsePhaseIsRejected(t *testing.T) {
	doc := `{"http":[{"match":{},"response":[{"action":"webhook","params":{"socket":"/run/approve.sock"}}]}]}`
	mustFailCompile(t, doc)
}
