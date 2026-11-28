// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
)

func TestReadVersionReportsModuleAndVCSState(t *testing.T) {
	build := func(version string, settings ...debug.BuildSetting) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Version: version}, Settings: settings}
	}
	for _, tc := range []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{"installed tag", build("v0.1.0"), "gateway v0.1.0"},
		{
			"dirty checkout",
			build("(devel)", debug.BuildSetting{Key: "vcs.revision", Value: "abc123"}, debug.BuildSetting{Key: "vcs.modified", Value: "true"}),
			"gateway (devel) revision=abc123 modified=true",
		},
		{
			"clean checkout",
			build("(devel)", debug.BuildSetting{Key: "vcs.revision", Value: "abc123"}, debug.BuildSetting{Key: "vcs.modified", Value: "false"}),
			"gateway (devel) revision=abc123 modified=false",
		},
	} {
		got, err := readVersion(tc.info, true)
		if err != nil || got.String() != tc.want {
			t.Errorf("%s: readVersion = %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}

	if got, err := readVersion(nil, false); err == nil {
		t.Errorf("missing build info reported as %q, want an error", got)
	}
	if got, err := readVersion(build(""), true); err == nil {
		t.Errorf("empty module version reported as %q, want an error", got)
	}
}

func TestVersionCommandAndFlag(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	want, err := readVersion(info, ok)
	if err != nil {
		t.Fatalf("test binary has no version: %v", err)
	}
	for _, args := range [][]string{{"version"}, {"--version"}} {
		var out, errOut bytes.Buffer
		if err := run(context.Background(), args, &out, &errOut); err != nil || out.String() != want.String()+string(rune(10)) {
			t.Fatalf("%v: output %q, err %v; want %q", args, out.String(), err, want)
		}
	}

	var out, errOut bytes.Buffer
	if err := run(context.Background(), []string{"version", "--json"}, &out, &errOut); err != nil {
		t.Fatalf("version --json: %v", err)
	}
	var got versionInfo
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got != want {
		t.Fatalf("version --json = %q (%v), want %+v", out.String(), err, want)
	}

	if err := run(context.Background(), []string{"version", "extra"}, &out, &errOut); err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Fatalf("version with an argument: err = %v", err)
	}
}
