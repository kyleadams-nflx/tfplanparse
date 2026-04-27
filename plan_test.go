package tfplanparse

import (
	"testing"
)

func TestIsJSONEncodeAttributeTerminator(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		line string
		want bool
	}{
		"bare_paren": {
			line: "                  )",
			want: true,
		},
		"bare_paren_trimmed": {
			line: ")",
			want: true,
		},
		"known_after_apply": {
			line: "        ) -> (known after apply)",
			want: true,
		},
		"arrow_null_suffix": {
			line: "        ) -> null",
			want: true,
		},
		"arrow_other": {
			line: "        ) -> (sensitive value)",
			want: true,
		},
		"not_closing": {
			line: "        + foo = \"bar\"",
			want: false,
		},
		"paren_without_arrow_suffix": {
			line: "        ) trailing junk",
			want: false,
		},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := IsJSONEncodeAttributeTerminator(tc.line); got != tc.want {
				t.Fatalf("IsJSONEncodeAttributeTerminator(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

func TestParseFromFile_jsonencodeStdout_terminatorEdgeAttributes(t *testing.T) {
	t.Parallel()
	changes, err := ParseFromFile("test/jsonencode.stdout")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("len(changes) = %d, want 1", len(changes))
	}
	rc := changes[0]
	var policyKnown, policyNullClose *JSONEncodeAttributeChange
	for _, ac := range rc.AttributeChanges {
		switch v := ac.(type) {
		case *JSONEncodeAttributeChange:
			switch v.Name {
			case "policy_known":
				policyKnown = v
			case "policy_null_close":
				policyNullClose = v
			}
		}
	}
	if policyKnown == nil {
		t.Fatal("missing top-level policy_known jsonencode attribute")
	}
	if policyNullClose == nil {
		t.Fatal("missing top-level policy_null_close jsonencode attribute")
	}
	if policyKnown.GetUpdateType() != DestroyResource {
		t.Errorf("policy_known update type = %v, want destroyed", policyKnown.GetUpdateType())
	}
	if policyNullClose.GetUpdateType() != DestroyResource {
		t.Errorf("policy_null_close update type = %v, want destroyed", policyNullClose.GetUpdateType())
	}
	beforeKnown := policyKnown.GetBefore()
	mKnown, ok := beforeKnown.(map[string]interface{})
	if !ok {
		t.Fatalf("policy_known GetBefore() type = %T, want map", beforeKnown)
	}
	innerKnown, ok := mKnown[""].(map[string]interface{})
	if !ok || innerKnown["k"] != "v" {
		t.Errorf("policy_known GetBefore() = %#v, want anonymous map entry with k=v", beforeKnown)
	}
	beforeNull := policyNullClose.GetBefore()
	mNull, ok := beforeNull.(map[string]interface{})
	if !ok {
		t.Fatalf("policy_null_close GetBefore() type = %T, want map", beforeNull)
	}
	innerNull, ok := mNull[""].(map[string]interface{})
	if !ok || innerNull["m"] != "n" {
		t.Errorf("policy_null_close GetBefore() = %#v, want anonymous map entry with m=n", beforeNull)
	}
}
