// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yuya Uwatoko

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/dataexchange"
)

// check re-verifies every vector from its serialized fields only (hex, JSON
// strings), using the Pilot code, so a vector cannot pass because of state
// that is not written out.
func check(v Vectors) error {
	var s Scope
	if err := strictJSON([]byte(v.Fixture.ScopeJSON), &s); err != nil {
		return fmt.Errorf("fixture scope_json: %w", err)
	}
	if s.Hash() != v.Fixture.ScopeHash || s.purpose() != v.Fixture.Purpose {
		return fmt.Errorf("fixture scope hash/purpose")
	}
	parties := map[string]Participant{}
	for _, p := range v.Fixture.Parties {
		for seed, want := range map[string]string{p.IntentSeed: p.IntentKey, p.AuthoritySeed: p.AuthorityKey} {
			b, _ := hex.DecodeString(seed)
			if len(b) != ed25519.SeedSize || hex.EncodeToString(ed25519.NewKeyFromSeed(b).Public().(ed25519.PublicKey)) != want {
				return fmt.Errorf("fixture party %s: seed does not give its public key", p.Party)
			}
		}
		parties[p.Party] = p.Participant
	}
	ids := map[string]bool{}
	unique := func(id string) error {
		if ids[id] {
			return fmt.Errorf("duplicate vector id %s", id)
		}
		ids[id] = true
		return nil
	}
	at := time.Unix(v.Fixture.T0+5, 0)

	objs := append(append(append([]ObjectVec(nil), v.Objects.Mandates...), v.Objects.Intents...), v.Objects.Decisions...)
	for _, o := range objs {
		if err := unique(o.ID); err != nil {
			return err
		}
		if err := checkObject(o, at); err != nil {
			return fmt.Errorf("%s: %w", o.ID, err)
		}
	}
	for _, p := range v.Objects.PayloadHashes {
		b, _ := hex.DecodeString(p.PayloadHex)
		if err := unique(p.ID); err != nil {
			return err
		}
		if dataexchange.GovernedPayloadHash(p.FrameType, p.Filename, b) != p.Hash {
			return fmt.Errorf("%s: payload hash", p.ID)
		}
	}
	for _, p := range v.Frames.Plain {
		raw, _ := hex.DecodeString(p.FrameHex)
		r := bytes.NewReader(raw)
		f, err := dataexchange.ReadFrame(r)
		if err := unique(p.ID); err != nil {
			return err
		}
		if err != nil || r.Len() != 0 || f.Type != p.Type || string(f.Payload) != p.Payload {
			return fmt.Errorf("%s: plain frame does not decode to its type/payload", p.ID)
		}
	}
	frames := append(append([]FrameVec(nil), v.Frames.Governed...), v.Negative...)
	for n, fv := range frames {
		if err := unique(fv.ID); err != nil {
			return err
		}
		if (n < len(v.Frames.Governed)) != fv.Expect.Accept {
			return fmt.Errorf("%s: accept flag is in the wrong list", fv.ID)
		}
		raw, _ := hex.DecodeString(fv.FrameHex)
		peer, ok := parties[fv.Sender]
		if !ok {
			return fmt.Errorf("%s: unknown sender", fv.ID)
		}
		got := receive(raw, fv.Receiver, peer, s, time.Unix(fv.VerifyAt, 0))
		if got.Code != fv.Expect.Code || got.Stage != fv.Expect.Stage {
			return fmt.Errorf("%s: got %s at %s (%v), want %s at %s", fv.ID, got.Code, got.Stage, got.Err, fv.Expect.Code, fv.Expect.Stage)
		}
		if fv.Expect.PilotError != "" && (got.Err == nil || !strings.Contains(got.Err.Error(), fv.Expect.PilotError)) {
			return fmt.Errorf("%s: error %v does not contain %q", fv.ID, got.Err, fv.Expect.PilotError)
		}
		if fv.Expect.Accept {
			r := bytes.NewReader(raw)
			f, _ := dataexchange.ReadFrame(r)
			g, _ := dataexchange.DecodeGovernedFrame(f)
			if r.Len() != 0 || string(f.Payload) != fv.Envelope || string(g.Payload) != fv.InnerText || must(g.Intent.Hash()) != fv.IntentHash || g.Decision.IntentHash != fv.IntentHash {
				return fmt.Errorf("%s: frame does not match its envelope/inner payload/intent hash", fv.ID)
			}
		}
	}
	return nil
}

type signed interface {
	Canonical() ([]byte, error)
	Hash() (string, error)
	Verify(ed25519.PublicKey, time.Time) error
}

func checkObject(o ObjectVec, at time.Time) error {
	var obj signed
	var sig string
	d := json.NewDecoder(strings.NewReader(o.JSON))
	d.DisallowUnknownFields()
	switch o.Kind {
	case "mandate":
		var m decision.Mandate
		if err := d.Decode(&m); err != nil {
			return err
		}
		obj, sig = m, m.Signature
	case "intent":
		var i decision.Intent
		if err := d.Decode(&i); err != nil {
			return err
		}
		obj, sig = i, i.Signature
	case "decision":
		var x decision.Decision
		if err := d.Decode(&x); err != nil {
			return err
		}
		obj, sig = x, x.Signature
	default:
		return fmt.Errorf("unknown kind %q", o.Kind)
	}
	canonical, err := obj.Canonical()
	if err != nil {
		return err
	}
	if hex.EncodeToString(canonical) != o.CanonicalHex || must(obj.Hash()) != o.Hash || sig != o.Signature {
		return fmt.Errorf("canonical/hash/signature fields disagree with the JSON")
	}
	pk, _ := hex.DecodeString(o.SignerPublic)
	raw, err := base64.StdEncoding.DecodeString(o.Signature)
	if err != nil || !ed25519.Verify(pk, canonical, raw) {
		return fmt.Errorf("signature does not verify over canonical bytes")
	}
	return obj.Verify(pk, at)
}
