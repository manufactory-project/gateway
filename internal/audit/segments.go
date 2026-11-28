// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Segments lists the audit segment files in dir, oldest first (by day, then by
// rotation sequence), for readers such as `gateway audit`.
func Segments(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("audit: read directory %s: %w", dir, err)
	}
	type seg struct {
		path, day string
		seq       int
	}
	var segs []seg
	for _, e := range entries {
		if day, seq, ok := parseSegmentName(e.Name()); ok && !e.IsDir() {
			segs = append(segs, seg{filepath.Join(dir, e.Name()), day, seq})
		}
	}
	sort.Slice(segs, func(i, j int) bool {
		if segs[i].day != segs[j].day {
			return segs[i].day < segs[j].day
		}
		return segs[i].seq < segs[j].seq
	})
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = s.path
	}
	return out, nil
}
