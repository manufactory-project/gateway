// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"runtime/debug"
)

// versionInfo identifies the build: the module version (the tag under
// `go install ...@v0.1.0`) and, for builds from a checkout, the VCS state.
type versionInfo struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	Modified bool   `json:"modified,omitempty"`
}

func readVersion(info *debug.BuildInfo, ok bool) (versionInfo, error) {
	if !ok || info.Main.Version == "" {
		return versionInfo{}, errors.New("version: this binary carries no module version")
	}
	v := versionInfo{Version: info.Main.Version}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			v.Revision = s.Value
		case "vcs.modified":
			v.Modified = s.Value == "true"
		}
	}
	return v, nil
}

func (v versionInfo) String() string {
	if v.Revision == "" {
		return "gateway " + v.Version
	}
	return fmt.Sprintf("gateway %s revision=%s modified=%t", v.Version, v.Revision, v.Modified)
}

func runVersion(args []string, jsonOut bool, stdout, stderr io.Writer) error {
	if err := parseNoArgs("gateway version", args, stderr); err != nil {
		return err
	}
	v, err := readVersion(debug.ReadBuildInfo())
	if err != nil {
		return err
	}
	if jsonOut {
		return printJSON(stdout, v)
	}
	_, err = fmt.Fprintln(stdout, v)
	return err
}
