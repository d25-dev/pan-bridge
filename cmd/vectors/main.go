// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yuya Uwatoko

// Command vectors writes the deterministic pan-protocol test vectors for
// WIRE_FORMAT.md using the Pilot Protocol packages the Client links.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/dataexchange"
)

// T0 is the fixed "now" of every vector (2030-01-01T00:00:00Z).
const T0 int64 = 1893456000

type party struct {
	Participant
	intent, authority ed25519.PrivateKey
}

func seed(label string) []byte { h := sha256.Sum256([]byte("pan-vectors/" + label)); return h[:] }

func newParty(name, addr string) *party {
	p := &party{intent: ed25519.NewKeyFromSeed(seed(name + "/intent")), authority: ed25519.NewKeyFromSeed(seed(name + "/authority"))}
	p.Participant = Participant{Party: name, Addr: addr, TransportKey: hex.EncodeToString(seed(name + "/transport")),
		IntentKey: hex.EncodeToString(p.intent.Public().(ed25519.PublicKey)), AuthorityKey: hex.EncodeToString(p.authority.Public().(ed25519.PublicKey))}
	return p
}

var (
	alice = newParty("alice", "0:0000.0000.0001")
	bob   = newParty("bob", "0:0000.0000.0002")
	carol = newParty("carol", "0:0000.0000.0003") // not a participant; used for wrong-key cases
	scope = Scope{SchemaVersion: 1, CaseID: "case-0123456789abcdef", Generation: 1, TemplateID: TemplateID, PurposeCode: PurposeCode, Initiator: "alice",
		Participants: []Participant{alice.Participant, bob.Participant},
		Catalog:      map[string]string{"s1": "2030-01-02 09:00", "s2": "2030-01-02 10:00", "s3": "2030-01-02 11:00", "s4": "2030-01-03 09:00"},
		Disclosure:   map[string][]string{"alice": {"s1", "s2"}, "bob": {"s2", "s3"}},
		Actions:      []string{"offer", "result", "confirm_result"}, MaxMessagesPerSide: MaxPerSide, MaxPayload: MaxPayload, ExpiresAt: T0 + 86400, PolicyRevision: 1}
	mandateIssuedAt = T0 - 3600
	escapeScope     = func() Scope {
		e := scope
		e.CaseID = "case-escape-0001"
		e.Catalog = map[string]string{
			"s1": "a<b>&c" + string(rune(0x2028)) + "d" + string(rune(0x2029)) + "e",
			"s2": "q\"uote\\back" + string(rune(0x01)) + "ctl",
			"s3": "日本 caf" + string(rune(0xe9)),
			"s4": "plain"}
		return e
	}()
)

func nonce(label string) string { return hex.EncodeToString(seed("nonce/" + label)[:16]) }

func must[T any](v T, err error) T {
	if err != nil {
		log.Panic(err)
	}
	return v
}

func msgJSON(m Message) []byte { return must(json.Marshal(m)) }

// proof describes one governed frame. The zero values reproduce the Client's
// Proof(); the hooks create the negative variants.
type proof struct {
	from, to   *party
	kind, id   string
	payload    []byte
	issuedAt   int64
	innerType  uint32
	filename   string
	disclosure *decision.DisclosureBinding
	intentKey  ed25519.PrivateKey
	authKey    ed25519.PrivateKey
	editIntent func(*decision.Intent)
	editDec    func(*decision.Decision)
	after      func(*dataexchange.GovernedFrame)
}

func (p proof) build() dataexchange.GovernedFrame {
	if p.issuedAt == 0 {
		p.issuedAt = T0
	}
	if p.innerType == 0 {
		p.innerType = dataexchange.TypeText
	}
	if p.intentKey == nil {
		p.intentKey = p.from.intent
	}
	if p.authKey == nil {
		p.authKey = p.from.authority
	}
	until := min(p.issuedAt+proofTTL, scope.ExpiresAt)
	self, peer := p.from.Party, p.to.Party
	i := decision.Intent{Version: decision.SchemaVersion, ID: p.id, TenantID: Tenant, AgentID: self, Action: dataexchange.GovernedAction(p.innerType), Resource: resource(p.kind, peer, scope),
		MandateID: scope.CaseID + "-" + self, Audience: "agent:" + peer, Purpose: scope.purpose(), PayloadHash: dataexchange.GovernedPayloadHash(p.innerType, p.filename, p.payload),
		Risk: decision.RiskMedium, IssuedAt: p.issuedAt, ExpiresAt: until, Nonce: nonce(p.id + "/" + fmt.Sprint(p.issuedAt)), KeyID: self + "-intent"}
	if p.disclosure != nil {
		i.PayloadHash = must(p.disclosure.Hash())
	}
	if p.editIntent != nil {
		p.editIntent(&i)
	}
	if err := i.Sign(p.intentKey); err != nil {
		log.Panic(err)
	}
	d := decision.Decision{Version: decision.SchemaVersion, ID: "decision-" + p.id, IntentHash: must(i.Hash()), TenantID: Tenant, AgentID: self, Outcome: decision.Allow,
		PolicyRevision: scope.PolicyRevision, RevocationEpoch: scope.Generation, ProviderID: self + "-authority", IssuedAt: p.issuedAt, ExpiresAt: until, KeyID: self + "-authority"}
	if p.editDec != nil {
		p.editDec(&d)
	}
	if err := d.Sign(p.authKey); err != nil {
		log.Panic(err)
	}
	g := dataexchange.GovernedFrame{Version: 1, Type: p.innerType, Filename: p.filename, Payload: append([]byte(nil), p.payload...), Disclosure: p.disclosure, Intent: i, Decision: d}
	if p.after != nil {
		p.after(&g)
	}
	return g
}

// rawFrame encodes g without validation (so negative frames can be built).
func rawFrame(g dataexchange.GovernedFrame) []byte {
	return frameBytes(dataexchange.TypeGoverned, must(json.Marshal(g)))
}

func frameBytes(typ uint32, payload []byte) []byte {
	var b bytes.Buffer
	if err := dataexchange.WriteFrame(&b, &dataexchange.Frame{Type: typ, Payload: payload}); err != nil {
		log.Panic(err)
	}
	return b.Bytes()
}

// clientFrame encodes g exactly as the Client does (validated Pilot encoder).
func clientFrame(g dataexchange.GovernedFrame) []byte {
	f := must(dataexchange.EncodeGovernedFrame(g))
	var b bytes.Buffer
	if err := dataexchange.WriteFrame(&b, f); err != nil {
		log.Panic(err)
	}
	if !bytes.Equal(b.Bytes(), rawFrame(g)) {
		log.Panic("validated and raw encodings differ")
	}
	return b.Bytes()
}

// ---- output schema (documented in pan-protocol/vectors/README.md) ----

type PartyVec struct {
	Participant
	IntentSeed    string `json:"intent_seed"`
	AuthoritySeed string `json:"authority_seed"`
}

type Fixture struct {
	Description string     `json:"description"`
	Generator   string     `json:"generator"`
	Tenant      string     `json:"tenant"`
	T0          int64      `json:"t0"`
	FrameCap    int        `json:"frame_cap"`
	MaxEnvelope int        `json:"max_envelope"`
	ProofTTL    int64      `json:"proof_ttl"`
	Parties     []PartyVec `json:"parties"`
	ScopeJSON   string     `json:"scope_json"`
	ScopeHash   string     `json:"scope_hash"`
	// EscapeScope exercises Go JSON string escaping in the scope hash (WIRE_FORMAT §8.2): catalog values with
	// < > & U+2028 U+2029, a quote, a backslash, a control character and non-ASCII text.
	EscapeScopeJSON string `json:"escape_scope_json"`
	EscapeScopeHash string `json:"escape_scope_hash"`
	Purpose         string `json:"purpose"`
	MandateIAt      int64  `json:"mandate_issued_at"`
}

type ObjectVec struct {
	ID           string `json:"id"`
	Description  string `json:"description"`
	Kind         string `json:"kind"` // mandate | intent | decision
	SignerPublic string `json:"signer_public"`
	JSON         string `json:"json"`
	CanonicalHex string `json:"canonical_hex"`
	Hash         string `json:"hash"`
	Signature    string `json:"signature"`
}

type PayloadHashVec struct {
	ID         string `json:"id"`
	FrameType  uint32 `json:"frame_type"`
	Filename   string `json:"filename"`
	PayloadHex string `json:"payload_hex"`
	Hash       string `json:"hash"`
}

type PlainFrameVec struct {
	ID       string `json:"id"`
	Type     uint32 `json:"type"`
	Payload  string `json:"payload"`
	FrameHex string `json:"frame_hex"`
}

type Expect struct {
	Accept     bool   `json:"accept"`
	Code       string `json:"code"`
	Stage      string `json:"stage"`
	Rule       string `json:"rule"`
	PilotError string `json:"-"` // checked against the in-memory vectors only; not published (it would quote Pilot error text)
}

type FrameVec struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Sender      string `json:"sender"`
	Receiver    string `json:"receiver"`
	VerifyAt    int64  `json:"verify_at"`
	FrameHex    string `json:"frame_hex"`
	Envelope    string `json:"envelope_json,omitempty"`
	InnerText   string `json:"inner_payload,omitempty"`
	IntentHash  string `json:"intent_hash,omitempty"`
	Expect      Expect `json:"expect"`
}

type Objects struct {
	Mandates      []ObjectVec      `json:"mandates"`
	Intents       []ObjectVec      `json:"intents"`
	Decisions     []ObjectVec      `json:"decisions"`
	PayloadHashes []PayloadHashVec `json:"payload_hashes"`
}

type Frames struct {
	Plain    []PlainFrameVec `json:"plain"`
	Governed []FrameVec      `json:"governed"`
}

type Vectors struct {
	Fixture  Fixture
	Objects  Objects
	Frames   Frames     // positive governed frames
	Negative []FrameVec // rejected frames
	V2       V2         // profile v2 (delegated case keys)
}

func objVec(id, desc, kind string, pub ed25519.PublicKey, v any, canonical []byte, hash, sig string) ObjectVec {
	return ObjectVec{ID: id, Description: desc, Kind: kind, SignerPublic: hex.EncodeToString(pub), JSON: string(must(json.Marshal(v))),
		CanonicalHex: hex.EncodeToString(canonical), Hash: hash, Signature: sig}
}

func mandateVec(id, desc string, m decision.Mandate, pub ed25519.PublicKey) ObjectVec {
	return objVec(id, desc, "mandate", pub, m, must(m.Canonical()), must(m.Hash()), m.Signature)
}
func intentVec(id, desc string, i decision.Intent, pub ed25519.PublicKey) ObjectVec {
	return objVec(id, desc, "intent", pub, i, must(i.Canonical()), must(i.Hash()), i.Signature)
}
func decisionVec(id, desc string, d decision.Decision, pub ed25519.PublicKey) ObjectVec {
	return objVec(id, desc, "decision", pub, d, must(d.Canonical()), must(d.Hash()), d.Signature)
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// build produces every vector in memory, deterministically.
func build() Vectors {
	var v Vectors
	v.Fixture = Fixture{Description: "Shared inputs for all pan-protocol wire vectors. Seeds are Ed25519 RFC 8032 private seeds (hex). Synthetic data only.",
		Generator: "pan-bridge/cmd/vectors with github.com/pilot-protocol/common v0.5.13 and github.com/pilot-protocol/dataexchange v0.2.2",
		Tenant:    Tenant, T0: T0, FrameCap: FrameCap, MaxEnvelope: MaxPayload, ProofTTL: proofTTL,
		ScopeJSON: string(scope.JSON()), ScopeHash: scope.Hash(), Purpose: scope.purpose(), MandateIAt: mandateIssuedAt,
		EscapeScopeJSON: string(escapeScope.JSON()), EscapeScopeHash: escapeScope.Hash()}
	for _, p := range []*party{alice, bob, carol} {
		v.Fixture.Parties = append(v.Fixture.Parties, PartyVec{p.Participant, hex.EncodeToString(p.intent.Seed()), hex.EncodeToString(p.authority.Seed())})
	}

	// ---- Mandates ----
	gA := must(grant(alice.authority, "alice", "bob", scope, mandateIssuedAt))
	gB := must(grant(bob.authority, "bob", "alice", scope, mandateIssuedAt))
	generic := decision.Mandate{Version: 1, ID: "m-generic", TenantID: "t1", SubjectAgentID: "agent-1", Actions: []string{"data.send.text", "data.*", "a.b"},
		ResourcePrefixes: []string{"res:z", "res:a/", "*"}, Audience: "*", Purpose: "pürpose with ünicode",
		Constraints:       []decision.Constraint{{Key: "z", Operator: "eq", Value: "1"}, {Key: "a", Operator: "max", Value: "10"}, {Key: "a", Operator: "eq", Value: "x"}},
		RequiredApprovals: 2, RevocationEpoch: 7, IssuedAt: T0, ExpiresAt: T0 + 3600, KeyID: "issuer-1"}
	if err := generic.Sign(carol.authority); err != nil {
		log.Panic(err)
	}
	v.Objects.Mandates = []ObjectVec{
		mandateVec("mandate-grant-alice", "Client grant from alice (initiator) to bob; carried as the invite payload alice->bob.", gA, pub(alice.authority)),
		mandateVec("mandate-grant-bob", "Client grant from bob to alice; carried as the invite payload bob->alice.", gB, pub(bob.authority)),
		mandateVec("mandate-generic-sorting", "Not used by the profile. Pins list sorting (actions, resource prefixes, constraints by key/operator/value), optional fields and non-ASCII text.", generic, pub(carol.authority)),
	}

	// ---- Frames (positive) ----
	offerMsg := msgJSON(Message{Case: scope.CaseID, Generation: 1, ID: "j1-1", Kind: "offer", Candidate: "s2"})
	digest := resultDigest(scope, "s2")
	resultMsg := msgJSON(Message{Case: scope.CaseID, Generation: 1, ID: "result-1", Kind: "result", Candidate: "s2", Digest: digest})
	confirmMsg := msgJSON(Message{Case: scope.CaseID, Generation: 1, ID: "confirm-1", Kind: "confirm_result", Candidate: "s2", Digest: digest})
	revokeMsg := msgJSON(Message{Case: scope.CaseID, Generation: 1, ID: "revoke", Kind: "revoke"})

	offer := proof{from: alice, to: bob, kind: "inbox", id: "j1-1", payload: offerMsg}
	invite := proof{from: alice, to: bob, kind: "invite", id: "invite", payload: must(json.Marshal(gA))}
	positives := []struct {
		id, desc string
		p        proof
		code     string
		at       int64
	}{
		{"governed-invite-alice-bob", "Invite: alice's grant (Mandate JSON) to bob on resource .../invite/...", invite, "INVITE_OK", T0 + 5},
		{"governed-invite-bob-alice", "Invite: bob's grant to alice.", proof{from: bob, to: alice, kind: "invite", id: "invite", payload: must(json.Marshal(gB))}, "INVITE_OK", T0 + 5},
		{"governed-offer", "Offer from the initiator alice to bob (candidate disclosed by alice).", offer, "ACCEPTED", T0 + 5},
		{"governed-result", "Result from the non-initiator bob to alice with the result digest.", proof{from: bob, to: alice, kind: "inbox", id: "result-1", payload: resultMsg}, "ACCEPTED", T0 + 5},
		{"governed-confirm-result", "Confirmation from alice to bob.", proof{from: alice, to: bob, kind: "inbox", id: "confirm-1", payload: confirmMsg}, "ACCEPTED", T0 + 5},
		{"governed-revoke", "Revocation (control resource) from alice to bob.", proof{from: alice, to: bob, kind: "control", id: "revoke", payload: revokeMsg}, "CONTROL_OK", T0 + 5},
		{"governed-offer-at-expiry", "Same offer verified exactly at intent/decision expires_at: still valid (expiry is exclusive only after).", offer, "ACCEPTED", T0 + proofTTL},
		{"governed-offer-clock-skew", "Same offer verified 60 s before issued_at: accepted under the 60 s skew allowance.", offer, "ACCEPTED", T0 - 60},
	}
	for _, c := range positives {
		g := c.p.build()
		fb := clientFrame(g)
		v.Frames.Governed = append(v.Frames.Governed, FrameVec{ID: c.id, Description: c.desc, Sender: c.p.from.Party, Receiver: c.p.to.Party, VerifyAt: c.at,
			FrameHex: hex.EncodeToString(fb), Envelope: string(fb[8:]), InnerText: string(g.Payload), IntentHash: must(g.Intent.Hash()),
			Expect: Expect{Accept: true, Code: c.code, Stage: StagePass, Rule: "accept"}})
		if c.id == "governed-offer" {
			v.Objects.Intents = append(v.Objects.Intents, intentVec("intent-offer", "Intent of governed-offer (delegated domain: mandate_id/audience/purpose set).", g.Intent, pub(alice.intent)))
			v.Objects.Decisions = append(v.Objects.Decisions, decisionVec("decision-offer", "Decision of governed-offer.", g.Decision, pub(alice.authority)))
		}
		if c.id == "governed-invite-alice-bob" {
			v.Objects.Intents = append(v.Objects.Intents, intentVec("intent-invite", "Intent of governed-invite-alice-bob.", g.Intent, pub(alice.intent)))
			v.Objects.Decisions = append(v.Objects.Decisions, decisionVec("decision-invite", "Decision of governed-invite-alice-bob.", g.Decision, pub(alice.authority)))
		}
	}
	// Receiver leniency: accepted by the Pilot decoder, never produced by a conforming sender.
	gOffer := offer.build()
	var generic1 map[string]any
	_ = json.Unmarshal(must(json.Marshal(gOffer)), &generic1)
	generic1["disclosure"] = nil
	reordered := must(json.MarshalIndent(generic1, "", "  ")) // sorted keys, whitespace, explicit null
	v.Frames.Governed = append(v.Frames.Governed, FrameVec{ID: "governed-offer-envelope-variant", Description: "Offer envelope re-encoded with sorted keys, indentation and \"disclosure\": null. The reference receiver accepts it (signatures cover canonical bytes, not JSON); senders MUST NOT produce it; receivers MAY reject it.",
		Sender: "alice", Receiver: "bob", VerifyAt: T0 + 5, FrameHex: hex.EncodeToString(frameBytes(dataexchange.TypeGoverned, reordered)), Envelope: string(reordered), InnerText: string(offerMsg),
		IntentHash: must(gOffer.Intent.Hash()), Expect: Expect{Accept: true, Code: "ACCEPTED", Stage: StagePass, Rule: "accept-lenient"}})

	// Generic Intent/Decision vectors (not produced by the profile).
	plain := decision.Intent{Version: 1, ID: "intent-plain", TenantID: "t1", AgentID: "agent-1", Action: "data.send.text", Resource: "agent:x/inbox",
		PayloadHash: dataexchange.GovernedPayloadHash(dataexchange.TypeText, "", []byte("hi")), Risk: decision.RiskLow, IssuedAt: T0, ExpiresAt: T0 + 300, Nonce: nonce("plain"), KeyID: "k1"}
	must(0, plain.Sign(carol.intent))
	audOnly := plain
	audOnly.ID, audOnly.Audience, audOnly.Nonce = "intent-audience-only", "agent:x", nonce("aud")
	must(0, audOnly.Sign(carol.intent))
	v.Objects.Intents = append(v.Objects.Intents,
		intentVec("intent-plain", "Not used by the profile. No mandate_id/audience/purpose: base domain, optional trailer absent.", plain, pub(carol.intent)),
		intentVec("intent-audience-only", "Not used by the profile. Only audience set: delegated domain; empty mandate_id and purpose are still written.", audOnly, pub(carol.intent)))
	cons := decision.Decision{Version: 1, ID: "d-constrain", IntentHash: must(plain.Hash()), TenantID: "t1", AgentID: "agent-1", Outcome: decision.Constrain,
		Reasons:        []string{"second", "first"},
		Constraints:    []decision.Constraint{{Key: "bytes", Operator: "max", Value: "100"}, {Key: "bytes", Operator: "eq", Value: "5"}, {Key: "a", Operator: "require", Value: ""}},
		PolicyRevision: 3, RevocationEpoch: 2, ProviderID: "p1", IssuedAt: T0, ExpiresAt: T0 + 300, KeyID: "k2"}
	must(0, cons.Sign(carol.authority))
	v.Objects.Decisions = append(v.Objects.Decisions, decisionVec("decision-constrain", "Not used by the profile. Reasons keep their order; constraints are sorted.", cons, pub(carol.authority)))

	// ---- Payload hashes ----
	for _, c := range []struct {
		id    string
		typ   uint32
		name  string
		bytes []byte
	}{
		{"payload-text-empty", dataexchange.TypeText, "", nil},
		{"payload-text-offer", dataexchange.TypeText, "", offerMsg},
		{"payload-text-invite", dataexchange.TypeText, "", must(json.Marshal(gA))},
		{"payload-file-named", dataexchange.TypeFile, "a.txt", []byte("hello")},
	} {
		v.Objects.PayloadHashes = append(v.Objects.PayloadHashes, PayloadHashVec{c.id, c.typ, c.name, hex.EncodeToString(c.bytes), dataexchange.GovernedPayloadHash(c.typ, c.name, c.bytes)})
	}

	// ---- Plain frames (acknowledgements) ----
	for _, code := range []string{"ACCEPTED", "DUPLICATE", "INVITE_OK", "CONTROL_OK", "NOT_YET_ACTIVE", "BUSY", "DENIED_PROOF"} {
		v.Frames.Plain = append(v.Frames.Plain, PlainFrameVec{"ack-" + code, dataexchange.TypeText, code, hex.EncodeToString(frameBytes(dataexchange.TypeText, []byte(code)))})
	}
	v.Frames.Plain = append(v.Frames.Plain, PlainFrameVec{"text-empty", dataexchange.TypeText, "", hex.EncodeToString(frameBytes(dataexchange.TypeText, nil))})

	v.Negative = negatives(offer, invite, gA)
	v.V2, _ = buildV2()
	return v
}

func negatives(offer, invite proof, gA decision.Mandate) []FrameVec {
	var out []FrameVec
	add := func(id, desc string, frame []byte, at int64, code, stage, rule, perr string) {
		out = append(out, FrameVec{ID: id, Description: desc, Sender: "alice", Receiver: "bob", VerifyAt: at, FrameHex: hex.EncodeToString(frame),
			Expect: Expect{Code: code, Stage: stage, Rule: rule, PilotError: perr}})
	}
	with := func(p proof, f func(*proof)) proof { f(&p); return p }
	at := T0 + 5
	good := offer.build()
	env := must(json.Marshal(good))

	// Frame layer.
	hdr := frameBytes(dataexchange.TypeGoverned, nil)
	hdr[4], hdr[5], hdr[6], hdr[7] = 0x00, 0x01, 0x00, 0x01 // declares 65537 bytes
	add("frame-length-over-cap", "Header declares 65537 payload bytes (> 64 KiB cap); rejected before reading the payload.", hdr, at, "DENIED_FRAME", StageReadFrame, "F-CAP", "frame too large")
	full := clientFrame(good)
	add("frame-truncated", "Header declares the full envelope length but the stream ends 10 bytes early.", full[:len(full)-10], at, "DENIED_FRAME", StageReadFrame, "F-SHORT", "unexpected EOF")
	add("frame-header-short", "Only 5 bytes of the 8-byte header arrive.", full[:5], at, "DENIED_FRAME", StageReadFrame, "F-SHORT", "unexpected EOF")
	big := with(offer, func(p *proof) {
		p.payload = msgJSON(Message{Case: scope.CaseID, Generation: 1, ID: "j1-1", Kind: "offer", Candidate: string(bytes.Repeat([]byte("x"), 12000))})
	}).build()
	add("envelope-over-profile-limit", "Validly signed envelope whose outer payload is larger than 16384 bytes (but within the 64 KiB frame cap).", clientFrame(big), at, "DENIED_FRAME", StageProfileFrame, "P-ENVELOPE-SIZE", "")
	add("outer-type-text", "The offer envelope JSON sent as a plain text frame (type 1) instead of governed (type 8).", frameBytes(dataexchange.TypeText, env), at, "DENIED_FRAME", StageProfileFrame, "P-OUTER-TYPE", "")

	// Envelope decoding and Pilot structural validation.
	add("envelope-unknown-field", "Envelope with an extra top-level member \"x\".", frameBytes(dataexchange.TypeGoverned, append(env[:len(env)-1:len(env)-1], []byte(`,"x":1}`)...)), at, "DENIED_FRAME", StageDecodeGoverned, "G-JSON", "unknown field")
	add("envelope-trailing-data", "Envelope followed by a second JSON value.", frameBytes(dataexchange.TypeGoverned, append(append([]byte(nil), env...), []byte(` {}`)...)), at, "DENIED_FRAME", StageDecodeGoverned, "G-JSON", "trailing governed envelope data")
	add("envelope-version-2", "Envelope version 2.", rawFrame(with(offer, func(p *proof) { p.after = func(g *dataexchange.GovernedFrame) { g.Version = 2 } }).build()), at, "DENIED_FRAME", StageDecodeGoverned, "G-VERSION-TYPE", "invalid governed frame type")
	add("payload-hash-mismatch", "Inner payload changed after signing (candidate s2 -> s1); payload_hash no longer matches.", rawFrame(with(offer, func(p *proof) {
		p.after = func(g *dataexchange.GovernedFrame) {
			g.Payload = msgJSON(Message{Case: scope.CaseID, Generation: 1, ID: "j1-1", Kind: "offer", Candidate: "s1"})
		}
	}).build()), at, "DENIED_FRAME", StageDecodeGoverned, "G-PAYLOAD-HASH", "payload binding mismatch")
	add("text-with-filename", "Inner type text with filename \"a.txt\" (payload hash computed with the filename).", rawFrame(with(offer, func(p *proof) { p.filename = "a.txt" }).build()), at, "DENIED_FRAME", StageDecodeGoverned, "G-FILENAME", "filename is only valid for file frames")
	add("unsigned-decision", "Decision signature removed.", rawFrame(with(offer, func(p *proof) { p.after = func(g *dataexchange.GovernedFrame) { g.Decision.Signature = "" } }).build()), at, "DENIED_FRAME", StageDecodeGoverned, "G-UNSIGNED", "must be signed")
	add("action-type-mismatch", "Inner type text but the Intent action is data.send.json.", rawFrame(with(offer, func(p *proof) { p.editIntent = func(i *decision.Intent) { i.Action = "data.send.json" } }).build()), at, "DENIED_FRAME", StageDecodeGoverned, "G-ACTION", "action does not match frame type")
	add("intent-ttl-too-long", "Intent validity window 301 s (> 300 s maximum).", rawFrame(with(offer, func(p *proof) {
		p.after = func(g *dataexchange.GovernedFrame) { g.Intent.ExpiresAt = g.Intent.IssuedAt + 301 }
	}).build()), at, "DENIED_FRAME", StageDecodeGoverned, "G-INTENT", "validity exceeds")
	add("intent-nonce-uppercase", "Intent nonce in uppercase hex.", rawFrame(with(offer, func(p *proof) {
		p.after = func(g *dataexchange.GovernedFrame) { g.Intent.Nonce = "0123456789ABCDEF0123456789ABCDEF" }
	}).build()), at, "DENIED_FRAME", StageDecodeGoverned, "G-INTENT", "nonce must be 32 lowercase hex")

	// Profile checks on the decoded inner frame.
	add("inner-type-json", "Validly signed governed JSON frame (type 3, action data.send.json).", rawFrame(with(offer, func(p *proof) { p.innerType = dataexchange.TypeJSON }).build()), at, "DENIED_FRAME", StageProfileInner, "P-INNER", "")
	add("inner-type-file", "Validly signed governed file frame (type 4, filename a.txt, action file.share).", rawFrame(with(offer, func(p *proof) { p.innerType, p.filename = dataexchange.TypeFile, "a.txt" }).build()), at, "DENIED_FRAME", StageProfileInner, "P-INNER", "")
	disc := decision.DisclosureBinding{Version: 1, ContentHash: decision.HashPayload(offer.payload), DeclaredBytes: uint64(len(offer.payload)), ContentType: "application/json",
		Labels: []string{"schedule"}, Recipient: "agent:bob", Purpose: scope.purpose(), Residency: "eu"}
	add("disclosure-present", "Validly bound disclosure object present (payload_hash is the disclosure hash).", rawFrame(with(offer, func(p *proof) { p.disclosure = &disc }).build()), at, "DENIED_FRAME", StageProfileInner, "P-INNER", "")
	add("resource-other-receiver", "Resource names carol, not the receiver bob.", rawFrame(with(offer, func(p *proof) {
		p.editIntent = func(i *decision.Intent) { i.Resource = resource("inbox", "carol", scope) }
	}).build()), at, "DENIED_RESOURCE", StageProfileResource, "P-RESOURCE", "")
	add("resource-unknown-case", "Resource names a case the receiver does not have.", rawFrame(with(offer, func(p *proof) {
		p.editIntent = func(i *decision.Intent) { i.Resource = "agent:bob/inbox/case-ffffffffffffffff/g1" }
	}).build()), at, "DENIED_UNKNOWN_CASE", StageProfileResource, "P-CASE", "")

	// Signatures, keys and bindings.
	add("intent-tampered-after-signing", "Intent risk changed medium -> high after signing.", rawFrame(with(offer, func(p *proof) { p.after = func(g *dataexchange.GovernedFrame) { g.Intent.Risk = decision.RiskHigh } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-INTENT-SIG", "intent signature verification failed")
	add("decision-tampered-after-signing", "Decision id changed after signing.", rawFrame(with(offer, func(p *proof) { p.after = func(g *dataexchange.GovernedFrame) { g.Decision.ID = "decision-x" } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-DECISION-SIG", "decision signature verification failed")
	add("intent-wrong-key", "Intent signed with carol's intent key but claims key_id alice-intent.", rawFrame(with(offer, func(p *proof) { p.intentKey = carol.intent }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-INTENT-SIG", "intent signature verification failed")
	add("decision-wrong-key", "Decision signed with alice's intent key instead of her authority key.", rawFrame(with(offer, func(p *proof) { p.authKey = alice.intent }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-DECISION-SIG", "decision signature verification failed")
	add("intent-signature-bad-base64", "Intent signature is unpadded base64.", rawFrame(with(offer, func(p *proof) {
		p.after = func(g *dataexchange.GovernedFrame) {
			g.Intent.Signature = g.Intent.Signature[:len(g.Intent.Signature)-2]
		}
	}).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-INTENT-SIG", "invalid intent signature encoding")
	add("intent-key-id-unknown", "Intent key_id alice-authority (only alice-intent is pinned for intents).", rawFrame(with(offer, func(p *proof) { p.editIntent = func(i *decision.Intent) { i.KeyID = "alice-authority" } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-INTENT-KEY", "resolve intent key")
	add("decision-key-id-unknown", "Decision key_id bob-authority (the sender is alice).", rawFrame(with(offer, func(p *proof) { p.editDec = func(d *decision.Decision) { d.KeyID = "bob-authority" } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-DECISION-KEY", "resolve decision key")
	add("intent-expired", "Verified at T0+61; the Intent expired at T0+60.", rawFrame(good), T0+61, "DENIED_PROOF", StageVerifyGoverned, "V-INTENT-FRESH", "intent is expired")
	add("intent-not-yet-valid", "Verified at T0-61; issued_at is more than 60 s in the future.", rawFrame(good), T0-61, "DENIED_PROOF", StageVerifyGoverned, "V-INTENT-FRESH", "intent is not yet valid")
	add("decision-expired", "Decision expires at T0+30 (before the Intent); verified at T0+31.", rawFrame(with(offer, func(p *proof) { p.editDec = func(d *decision.Decision) { d.ExpiresAt = T0 + 30 } }).build()), T0+31, "DENIED_PROOF", StageVerifyGoverned, "V-DECISION-FRESH", "decision is expired")
	other := with(offer, func(p *proof) { p.id = "j1-2" }).build()
	add("decision-bound-to-other-intent", "Correctly signed Decision whose intent_hash is that of a different Intent.", rawFrame(with(offer, func(p *proof) {
		p.editDec = func(d *decision.Decision) { d.IntentHash = must(other.Intent.Hash()) }
	}).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-BIND-HASH", "bound to a different intent")
	add("decision-agent-mismatch", "Correctly signed Decision bound to the right Intent hash but naming agent bob.", rawFrame(with(offer, func(p *proof) { p.editDec = func(d *decision.Decision) { d.AgentID = "bob" } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-BIND-TENANT-AGENT", "tenant or agent binding mismatch")
	add("decision-expiry-after-intent", "Decision expires_at T0+120 is later than the Intent's T0+60.", rawFrame(with(offer, func(p *proof) { p.editDec = func(d *decision.Decision) { d.ExpiresAt = T0 + 120 } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-BIND-EXPIRY", "decision expiry expands intent authority")
	add("decision-predates-intent", "Decision issued_at 61 s before the Intent's.", rawFrame(with(offer, func(p *proof) { p.editDec = func(d *decision.Decision) { d.IssuedAt = T0 - 61 } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-BIND-ISSUED", "decision predates intent")
	add("decision-stale-revocation-epoch", "Decision revocation_epoch 0 (minimum is the case generation 1).", rawFrame(with(offer, func(p *proof) { p.editDec = func(d *decision.Decision) { d.RevocationEpoch = 0 } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-STATE", "stale revocation epoch")
	add("decision-stale-policy-revision", "Decision policy_revision 0 (minimum is 1).", rawFrame(with(offer, func(p *proof) { p.editDec = func(d *decision.Decision) { d.PolicyRevision = 0 } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-STATE", "stale policy revision")
	add("ceiling-wrong-mandate-id", "Intent mandate_id names bob's grant instead of alice's.", rawFrame(with(offer, func(p *proof) { p.editIntent = func(i *decision.Intent) { i.MandateID = scope.CaseID + "-bob" } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-CEILING", "local authority ceiling")
	add("ceiling-wrong-purpose", "Intent purpose with a different scope hash.", rawFrame(with(offer, func(p *proof) {
		p.editIntent = func(i *decision.Intent) { i.Purpose = PurposeCode + ":" + sum([]byte("other")) }
	}).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-CEILING", "local authority ceiling")
	add("ceiling-decision-reasons", "Allow decision carrying a reason.", rawFrame(with(offer, func(p *proof) { p.editDec = func(d *decision.Decision) { d.Reasons = []string{"note"} } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-CEILING", "local authority ceiling")
	add("decision-outcome-deny", "Correctly signed Decision with outcome deny.", rawFrame(with(offer, func(p *proof) { p.editDec = func(d *decision.Decision) { d.Outcome = decision.Deny } }).build()), at, "DENIED_PROOF", StageVerifyGoverned, "V-OUTCOME", "cannot permit delivery")

	// Payload (profile) checks after the proof verifies.
	badGrant := gA
	badGrant.IssuedAt++
	add("invite-mandate-tampered", "Invite whose Mandate issued_at was changed after the Mandate was signed (the frame proof is valid for the changed bytes).", rawFrame(with(invite, func(p *proof) { p.payload = must(json.Marshal(badGrant)) }).build()), at, "DENIED_GRANT", StagePayload, "M-SIG", "mandate signature verification failed")
	wrongKey := gA
	must(0, wrongKey.Sign(alice.intent))
	add("invite-mandate-wrong-key", "Invite whose Mandate is signed with alice's intent key.", rawFrame(with(invite, func(p *proof) { p.payload = must(json.Marshal(wrongKey)) }).build()), at, "DENIED_GRANT", StagePayload, "M-SIG", "mandate signature verification failed")
	aud := gA
	aud.Audience = "agent:carol"
	must(0, aud.Sign(alice.authority))
	add("invite-mandate-wrong-audience", "Correctly signed Mandate for audience agent:carol.", rawFrame(with(invite, func(p *proof) { p.payload = must(json.Marshal(aud)) }).build()), at, "DENIED_GRANT", StagePayload, "M-PROFILE", "")
	add("invite-mandate-expired", "Correctly signed Mandate whose expires_at is T0 (verified at T0+5); the frame proof itself is valid.", rawFrame(with(invite, func(p *proof) {
		m := gA
		m.ExpiresAt = T0
		must(0, m.Sign(alice.authority))
		p.payload = must(json.Marshal(m))
	}).build()), at, "DENIED_GRANT", StagePayload, "M-FRESH", "mandate is expired")
	indented := must(json.MarshalIndent(gA, "", " "))
	add("invite-mandate-not-canonical-json", "Mandate JSON with indentation (not byte-identical to the canonical JSON encoding).", rawFrame(with(invite, func(p *proof) { p.payload = indented }).build()), at, "DENIED_GRANT", StagePayload, "M-JSON", "not the canonical JSON")
	add("message-id-mismatch", "Offer whose Intent id j1-2 differs from the message ID j1-1.", rawFrame(with(offer, func(p *proof) { p.id = "j1-2" }).build()), at, "DENIED_MESSAGE", StagePayload, "B-MESSAGE", "")
	add("message-not-canonical-json", "Offer message JSON with a space after a colon.", rawFrame(with(offer, func(p *proof) {
		p.payload = bytes.Replace(offer.payload, []byte(`"Kind":"offer"`), []byte(`"Kind": "offer"`), 1)
	}).build()), at, "DENIED_MESSAGE", StagePayload, "B-MESSAGE", "not the canonical JSON")
	add("offer-undisclosed-candidate", "Offer of s3, which alice does not disclose.", rawFrame(with(offer, func(p *proof) {
		p.payload = msgJSON(Message{Case: scope.CaseID, Generation: 1, ID: "j1-1", Kind: "offer", Candidate: "s3"})
	}).build()), at, "DENIED_MESSAGE", StagePayload, "B-MESSAGE", "")
	return out
}

func writeJSON(dir, name string, v any) error {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), b.Bytes(), 0o644)
}

// files maps each output file to its content.
func files(v Vectors) map[string]any {
	return map[string]any{"fixture.json": v.Fixture, "objects.json": v.Objects, "frames.json": v.Frames, "negative.json": v.Negative, "v2.json": v.V2}
}

func main() {
	out := flag.String("out", "", "output directory")
	flag.Parse()
	if *out == "" {
		log.Fatal("-out is required")
	}
	v := build()
	if err := check(v); err != nil {
		log.Fatal(err)
	}
	for name, content := range files(v) {
		if err := writeJSON(*out, name, content); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("wrote %d positive governed, %d plain, %d negative frame vectors; %d mandates, %d intents, %d decisions, %d payload hashes (T0=%s)\n",
		len(v.Frames.Governed), len(v.Frames.Plain), len(v.Negative), len(v.Objects.Mandates), len(v.Objects.Intents), len(v.Objects.Decisions), len(v.Objects.PayloadHashes),
		time.Unix(T0, 0).UTC().Format(time.RFC3339))
}
