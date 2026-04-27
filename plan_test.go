package tfplanparse

import (
	"reflect"
	"testing"
)

func TestIsResourceChangeLine(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		line string
		want bool
	}{
		"resource_block": {
			line: `  + resource "null_resource" "example" {`,
			want: true,
		},
		"data_block": {
			line: `       <= data "aws_caller_identity" "current" {`,
			want: true,
		},
		"attribute_map_named_resource_policy": {
			line: `            ~ resource_policy                      = {`,
			want: false,
		},
		"attribute_map_resource_arn": {
			line: `            ~ resource_arn                        = "arn:a" -> "arn:b"`,
			want: false,
		},
		"map_not_block": {
			line: `    + metadata = {`,
			want: false,
		},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := IsResourceChangeLine(tc.line); got != tc.want {
				t.Fatalf("IsResourceChangeLine(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

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

func TestParseFromFile_complexStdout_resourcePolicyWrapsPolicyDocument(t *testing.T) {
	t.Parallel()
	rcs, err := ParseFromFile("test/complex.stdout")
	if err != nil {
		t.Fatal(err)
	}
	var table *ResourceChange
	for _, rc := range rcs {
		if rc.Type == "awscc_dynamodb_table" && rc.Name == "main" && rc.UpdateType == ForceReplaceResource {
			table = rc
			break
		}
	}
	if table == nil {
		t.Fatal("expected force-replace awscc_dynamodb_table.main in complex.stdout")
	}
	var rp *MapAttributeChange
	for _, ac := range table.AttributeChanges {
		if m, ok := ac.(*MapAttributeChange); ok && m.Name == "resource_policy" {
			rp = m
			break
		}
	}
	if rp == nil {
		t.Fatal("expected resource_policy map at resource top level (not a mis-parsed resource header)")
	}
	if rp.GetUpdateType() != UpdateInPlaceResource {
		t.Fatalf("resource_policy update type = %v, want updateInPlace", rp.GetUpdateType())
	}
	var pol *JSONEncodeAttributeChange
	for _, ac := range rp.AttributeChanges {
		if j, ok := ac.(*JSONEncodeAttributeChange); ok && j.Name == "policy_document" {
			pol = j
			break
		}
	}
	if pol == nil {
		t.Fatal("expected policy_document jsonencode inside resource_policy")
	}
	if pol.GetUpdateType() != UpdateInPlaceResource {
		t.Fatalf("policy_document update type = %v, want updateInPlace", pol.GetUpdateType())
	}
}

func TestParseFromFile_jsonencodeMixStdout_updateKinds(t *testing.T) {
	t.Parallel()
	rcs, err := ParseFromFile("test/jsonencode_mix.stdout")
	if err != nil {
		t.Fatal(err)
	}
	if len(rcs) != 1 {
		t.Fatalf("len(rcs) = %d, want 1", len(rcs))
	}
	var pol *JSONEncodeAttributeChange
	for _, ac := range rcs[0].AttributeChanges {
		if j, ok := ac.(*JSONEncodeAttributeChange); ok && j.Name == "policy" {
			pol = j
			break
		}
	}
	if pol == nil {
		t.Fatal("missing policy jsonencode attribute")
	}
	var inner *MapAttributeChange
	for _, ac := range pol.AttributeChanges {
		if m, ok := ac.(*MapAttributeChange); ok && m.Name == "" {
			inner = m
			break
		}
	}
	if inner == nil {
		t.Fatalf("jsonencode children: %v", pol.AttributeChanges)
	}
	byName := map[string]*AttributeChange{}
	for _, ac := range inner.AttributeChanges {
		a, ok := ac.(*AttributeChange)
		if !ok {
			t.Fatalf("unexpected child type %T", ac)
		}
		byName[a.Name] = a
	}
	want := map[string]UpdateType{
		"only_old":  DestroyResource,
		"only_new":  NewResource,
		"both":      UpdateInPlaceResource,
	}
	for n, ut := range want {
		a, ok := byName[n]
		if !ok {
			t.Fatalf("missing attribute %q", n)
		}
		if a.UpdateType != ut {
			t.Fatalf("attribute %q: UpdateType = %v, want %v", n, a.UpdateType, ut)
		}
	}
	if !reflect.DeepEqual(byName["only_old"].OldValue, "x") || byName["only_old"].NewValue != nil {
		t.Fatalf("only_old values: %#v -> %#v", byName["only_old"].OldValue, byName["only_old"].NewValue)
	}
	if byName["only_new"].OldValue != nil || !reflect.DeepEqual(byName["only_new"].NewValue, "y") {
		t.Fatalf("only_new values: %#v -> %#v", byName["only_new"].OldValue, byName["only_new"].NewValue)
	}
	if !reflect.DeepEqual(byName["both"].OldValue, "a") || !reflect.DeepEqual(byName["both"].NewValue, "b") {
		t.Fatalf("both values: %#v -> %#v", byName["both"].OldValue, byName["both"].NewValue)
	}
}
