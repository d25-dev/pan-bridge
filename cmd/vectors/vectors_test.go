// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yuya Uwatoko

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/dataexchange"
)

var published = flag.String("published", "../../../pan-protocol/vectors", "directory of the published vectors to compare with (skipped if absent)")

// TestVectors verifies the published vector files with the Pilot code: every
// positive vector is accepted, every negative one is rejected at the stated
// stage with the stated code and Pilot error, and the files are exactly what
// the generator produces.
func TestVectors(t *testing.T) {
	if dataexchange.MaxFrameSize != FrameCap {
		t.Fatalf("frame cap %d", dataexchange.MaxFrameSize)
	}
	built := build()
	if err := check(built); err != nil {
		t.Fatal(err)
	}
	for name, content := range files(built) {
		var b bytes.Buffer
		e := json.NewEncoder(&b)
		e.SetEscapeHTML(false)
		e.SetIndent("", "  ")
		if err := e.Encode(content); err != nil {
			t.Fatal(err)
		}
		again := files(build())[name]
		if c, _ := json.Marshal(again); !bytes.Equal(c, must(json.Marshal(content))) {
			t.Fatalf("%s: generation is not deterministic", name)
		}
		disk, err := os.ReadFile(filepath.Join(*published, name))
		if os.IsNotExist(err) {
			t.Logf("%s: not published at %s; skipped comparison", name, *published)
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(disk, b.Bytes()) {
			t.Errorf("%s: published file differs from the generator output", name)
		}
	}
	// Verify what is on disk independently of build(): parse and check.
	var v Vectors
	for name, dst := range map[string]any{"fixture.json": &v.Fixture, "objects.json": &v.Objects, "frames.json": &v.Frames, "negative.json": &v.Negative} {
		b, err := os.ReadFile(filepath.Join(*published, name))
		if err != nil {
			t.Skipf("published vectors not readable: %v", err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := check(v); err != nil {
		t.Fatal(err)
	}
	t.Logf("verified %d positive governed, %d plain, %d negative frames; %d mandates, %d intents, %d decisions, %d payload hashes",
		len(v.Frames.Governed), len(v.Frames.Plain), len(v.Negative), len(v.Objects.Mandates), len(v.Objects.Intents), len(v.Objects.Decisions), len(v.Objects.PayloadHashes))
}
