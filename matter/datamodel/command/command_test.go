// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package command

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cybergarage/go-matter/matter/datamodel"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

const (
	onOffCluster        im.ClusterID = 0x0006
	levelControlCluster im.ClusterID = 0x0008
	doorLockCluster     im.ClusterID = 0x0101
	colorControlCluster im.ClusterID = 0x0300
)

func catalog(t *testing.T) *datamodel.Catalog {
	t.Helper()
	c, err := datamodel.Load()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func schema(t *testing.T, cluster im.ClusterID, command im.CommandID) *Schema {
	t.Helper()
	s, err := New(catalog(t), cluster, command)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func encode(t *testing.T, s *Schema, values map[string]any) string {
	t.Helper()
	b, err := s.Encode(values)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestEveryRequestCommandOfTheCatalogHasASchema(t *testing.T) {
	c := catalog(t)
	commands, fields, unsupported := 0, 0, 0
	for _, cluster := range c.Clusters {
		for _, cmd := range cluster.Commands {
			if cmd.Source != requestSource {
				continue
			}
			s, err := New(c, cluster.ID, cmd.ID)
			if err != nil {
				t.Errorf("%s %s: %v", cluster.Name, cmd.Name, err)
				continue
			}
			if s.CommandName != cmd.Name || s.Timed != cmd.Timed {
				t.Errorf("%s %s: schema identity", cluster.Name, cmd.Name)
			}
			commands++
			for i, f := range s.Fields {
				fields++
				if i > 0 && s.Fields[i-1].ID >= f.ID {
					t.Errorf("%s %s: fields are not in ID order", cluster.Name, cmd.Name)
				}
				if f.Kind == KindUnsupported {
					unsupported++
					if f.Unsupported == "" {
						t.Errorf("%s %s %s: no reason", cluster.Name, cmd.Name, f.Name)
					}
				}
			}
		}
	}
	if commands == 0 || fields == 0 {
		t.Fatal("no request commands found")
	}
	// Lists and structures are the only fields left out; a rise means a new
	// kind of field needs a look.
	if unsupported > 4 {
		t.Fatalf("%d of %d fields are unsupported", unsupported, fields)
	}
}

func TestUnknownClusterAndCommand(t *testing.T) {
	c := catalog(t)
	if _, err := New(c, 0x9999, 0); !errors.Is(err, ErrUnknownCommand) {
		t.Fatalf("unknown cluster: %v", err)
	}
	if _, err := New(c, onOffCluster, 0x7F); !errors.Is(err, ErrUnknownCommand) {
		t.Fatalf("unknown command: %v", err)
	}
}

func TestCommandWithoutFields(t *testing.T) {
	s := schema(t, onOffCluster, 1)
	if s.CommandName != "On" || s.ClusterName != "On/Off" || len(s.Fields) != 0 || s.Timed {
		t.Fatalf("schema = %+v", s)
	}
	// An empty CommandFields structure.
	if got := encode(t, s, nil); got != "350118" {
		t.Fatalf("fields = %s", got)
	}
	if _, err := s.Encode(map[string]any{"Level": 1}); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("unknown field: %v", err)
	}
}

func TestMoveToLevelFieldsAndEncoding(t *testing.T) {
	s := schema(t, levelControlCluster, 0)
	if s.CommandName != "MoveToLevel" || len(s.Fields) != 4 {
		t.Fatalf("schema = %+v", s)
	}
	level := s.Fields[0]
	if level.ID != 0 || level.Name != "Level" || level.Kind != KindUnsigned || level.Bits != 8 || level.UMax != 254 || level.Nullable {
		t.Fatalf("Level = %+v", level)
	}
	transition := s.Fields[1]
	if transition.ID != 1 || transition.Kind != KindUnsigned || transition.Bits != 16 || !transition.Nullable {
		t.Fatalf("TransitionTime = %+v", transition)
	}
	options := s.Fields[2]
	if options.Kind != KindBitmap || options.Bits != 8 || len(options.Choices) != 2 || options.Choices[0].Name != "ExecuteIfOff" || options.Choices[1].Value != 2 {
		t.Fatalf("OptionsMask = %+v", options)
	}

	// CommandFields is a structure with context tag 1; each field carries
	// its ID as a context tag. 10.7.9. InvokeRequestMessage.
	const want = "3501" + "240080" + "240100" + "240200" + "240300" + "18"
	got := encode(t, s, map[string]any{"Level": 128, "TransitionTime": 0, "OptionsMask": 0, "OptionsOverride": 0})
	if got != want {
		t.Fatalf("fields = %s, want %s", got, want)
	}
	// Text, as a command line gives it, and field names in another case.
	got = encode(t, s, map[string]any{"level": "0x80", "transitiontime": "0", "optionsmask": "0", "optionsoverride": "0"})
	if got != want {
		t.Fatalf("fields from text = %s, want %s", got, want)
	}
	// JSON numbers, as a decoded request body gives them.
	got = encode(t, s, map[string]any{"Level": float64(128), "TransitionTime": json.Number("0"), "OptionsMask": float64(0), "OptionsOverride": uint8(0)})
	if got != want {
		t.Fatalf("fields from JSON = %s, want %s", got, want)
	}

	// Null for the nullable field, a wider integer, and bitmap names.
	got = encode(t, s, map[string]any{"Level": 254, "TransitionTime": nil, "OptionsMask": "ExecuteIfOff|CoupleColorTempToLevel", "OptionsOverride": "executeifoff"})
	if got != "3501"+"2400fe"+"3401"+"240203"+"240301"+"18" {
		t.Fatalf("fields = %s", got)
	}
	got = encode(t, s, map[string]any{"Level": 1, "TransitionTime": "null", "OptionsMask": 0, "OptionsOverride": 0})
	if got != "3501"+"240001"+"3401"+"240200"+"240300"+"18" {
		t.Fatalf("fields = %s", got)
	}
	got = encode(t, s, map[string]any{"Level": 1, "TransitionTime": 300, "OptionsMask": 0, "OptionsOverride": 0})
	if got != "3501"+"240001"+"25012c01"+"240200"+"240300"+"18" {
		t.Fatalf("fields = %s", got)
	}
}

func TestMoveToLevelRejectsBadValues(t *testing.T) {
	s := schema(t, levelControlCluster, 0)
	base := func() map[string]any {
		return map[string]any{"Level": 1, "TransitionTime": 0, "OptionsMask": 0, "OptionsOverride": 0}
	}
	tests := []struct {
		name  string
		field string
		value any
		drop  bool
		want  error
	}{
		{"above the maximum", "Level", 255, false, ErrInvalidValue},
		{"negative", "Level", -1, false, ErrInvalidValue},
		{"fraction", "Level", 1.5, false, ErrInvalidValue},
		{"not a number", "Level", "bright", false, ErrInvalidValue},
		{"a bool for an integer", "Level", true, false, ErrInvalidValue},
		{"null for a field which is not nullable", "Level", nil, false, ErrInvalidValue},
		{"wider than the type", "TransitionTime", 65536, false, ErrInvalidValue},
		{"undefined bit", "OptionsMask", 4, false, ErrInvalidValue},
		{"unknown bit name", "OptionsMask", "ExecuteIfOn", false, ErrInvalidValue},
		{"missing mandatory field", "OptionsOverride", nil, true, ErrMissingField},
	}
	for _, tt := range tests {
		values := base()
		if tt.drop {
			delete(values, tt.field)
		} else {
			values[tt.field] = tt.value
		}
		if _, err := s.Encode(values); !errors.Is(err, tt.want) {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
	if _, err := s.Encode(map[string]any{"Level": 1, "level": 2, "TransitionTime": 0, "OptionsMask": 0, "OptionsOverride": 0}); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("field given twice: %v", err)
	}
}

func TestEnumFieldsUseTheScopeOfTheirCluster(t *testing.T) {
	// Level Control and Color Control both define MoveModeEnum, with
	// different values for Down.
	level := schema(t, levelControlCluster, 1)
	mode, ok := level.Field("MoveMode")
	if !ok || mode.Kind != KindEnum || len(mode.Choices) != 2 {
		t.Fatalf("Level Control MoveMode = %+v", mode)
	}
	got := encode(t, level, map[string]any{"MoveMode": "Down", "Rate": nil, "OptionsMask": 0, "OptionsOverride": 0})
	if got != "3501"+"240001"+"3401"+"240200"+"240300"+"18" {
		t.Fatalf("fields = %s", got)
	}
	if _, err := level.Encode(map[string]any{"MoveMode": 3, "Rate": nil, "OptionsMask": 0, "OptionsOverride": 0}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("undefined enum value: %v", err)
	}

	// MoveHue numbers its fields with fieldId, where Level Control uses id.
	color := schema(t, colorControlCluster, 1)
	mode, ok = color.Field("MoveMode")
	if !ok || mode.Kind != KindEnum || len(mode.Choices) != 3 {
		t.Fatalf("Color Control MoveMode = %+v", mode)
	}
	got = encode(t, color, map[string]any{"MoveMode": "Down", "Rate": 10, "OptionsMask": 0, "OptionsOverride": 0})
	if got != "3501"+"240003"+"24010a"+"240200"+"240300"+"18" {
		t.Fatalf("fields = %s", got)
	}
}

func TestColorControlMoveToHueAndSaturation(t *testing.T) {
	s := schema(t, colorControlCluster, 6)
	if s.CommandName != "MoveToHueAndSaturation" {
		t.Fatalf("command = %s", s.CommandName)
	}
	got := encode(t, s, map[string]any{"Hue": 170, "Saturation": 254, "TransitionTime": 10, "OptionsMask": 0, "OptionsOverride": 0})
	if got != "3501"+"2400aa"+"2401fe"+"24020a"+"240300"+"240400"+"18" {
		t.Fatalf("fields = %s", got)
	}
}

func TestOptionalOctetsAndTimedCommand(t *testing.T) {
	// LockDoor has an optional PINCode and has to be sent as a timed
	// invoke.
	s := schema(t, doorLockCluster, 0)
	if s.CommandName != "LockDoor" || !s.Timed {
		t.Fatalf("schema = %+v", s)
	}
	pin, ok := s.Field("PINCode")
	if !ok || pin.Kind != KindOctets || !pin.Optional {
		t.Fatalf("PINCode = %+v", pin)
	}
	if got := encode(t, s, nil); got != "350118" {
		t.Fatalf("fields without the optional field = %s", got)
	}
	if got := encode(t, s, map[string]any{"PINCode": "31323334"}); got != "3501"+"300004"+"31323334"+"18" {
		t.Fatalf("fields = %s", got)
	}
	if got := encode(t, s, map[string]any{"PINCode": []byte("1234")}); got != "3501"+"300004"+"31323334"+"18" {
		t.Fatalf("fields = %s", got)
	}
	if _, err := s.Encode(map[string]any{"PINCode": "12zz"}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("bad hexadecimal: %v", err)
	}
}

func TestSignedBoolAndUnsupportedFields(t *testing.T) {
	// MoveColor takes signed rates.
	s := schema(t, colorControlCluster, 8)
	rate, ok := s.Field("RateX")
	if !ok || rate.Kind != KindSigned || rate.Bits != 16 {
		t.Fatalf("RateX = %+v", rate)
	}
	got := encode(t, s, map[string]any{"RateX": -2, "RateY": "0x10", "OptionsMask": 0, "OptionsOverride": 0})
	if got != "3501"+"2000fe"+"200110"+"240200"+"240300"+"18" {
		t.Fatalf("fields = %s", got)
	}
	if _, err := s.Encode(map[string]any{"RateX": 40000, "RateY": 0, "OptionsMask": 0, "OptionsOverride": 0}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("out of the signed range: %v", err)
	}

	// SetCredential carries a CredentialStruct, which is not encoded here.
	c := catalog(t)
	lock, _ := c.Cluster(doorLockCluster)
	for _, cmd := range lock.Commands {
		if cmd.Name != "SetCredential" || cmd.Source != requestSource {
			continue
		}
		s := schema(t, doorLockCluster, cmd.ID)
		credential, ok := s.Field("Credential")
		if !ok || credential.Kind != KindUnsupported {
			t.Fatalf("Credential = %+v", credential)
		}
		if _, err := s.Encode(map[string]any{"Credential": "x"}); !errors.Is(err, ErrUnsupportedField) && !errors.Is(err, ErrMissingField) {
			t.Fatalf("structure field: %v", err)
		}
		return
	}
	t.Fatal("SetCredential not found")
}
