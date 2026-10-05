// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yuya Uwatoko

package main

// Profile v2 (pan-protocol spec/PROFILE_V2_DELEGATION.md): grants name a per-case delegate key in a constraint,
// and every Intent and Decision of the case is signed with that delegate key.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/dataexchange"
)

const DelegateKey = "pan.delegate.ed25519"

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

var (
	scopeV2 = func() Scope {
		s := scope
		s.SchemaVersion = 2
		s.CaseID = "case-v2-0123456789"
		return s
	}()
	delegateA     = ed25519.NewKeyFromSeed(seed("v2/alice/delegate/" + scopeV2.CaseID))
	delegateB     = ed25519.NewKeyFromSeed(seed("v2/bob/delegate/" + scopeV2.CaseID))
	delegateOther = ed25519.NewKeyFromSeed(seed("v2/alice/delegate/case-v2-other-case"))
)

func caseKeyID(party string, s Scope) string { return party + "-case-" + s.CaseID }

// grantV2 is the v1 grant plus exactly one delegate constraint, signed with the authority key.
func grantV2(signer ed25519.PrivateKey, self, peer string, s Scope, issuedAt int64, delegate ed25519.PublicKey, edit func(*decision.Mandate)) decision.Mandate {
	m := decision.Mandate{Version: decision.SchemaVersion, ID: s.CaseID + "-" + self, TenantID: Tenant, SubjectAgentID: self, Actions: []string{Action},
		ResourcePrefixes: []string{resource("inbox", peer, s)}, Audience: "agent:" + peer, Purpose: s.purpose(),
		Constraints:     []decision.Constraint{{Key: DelegateKey, Operator: "eq", Value: hex.EncodeToString(delegate)}},
		RevocationEpoch: s.Generation, IssuedAt: issuedAt, ExpiresAt: s.ExpiresAt, KeyID: self + "-authority"}
	if edit != nil {
		edit(&m)
	}
	if err := m.Sign(signer); err != nil {
		panic(err)
	}
	return m
}

// verifyGrantV2 checks a v2 grant of (from -> to, s) and returns the delegate key it names.
func verifyGrantV2(m *decision.Mandate, authority ed25519.PublicKey, from, to string, s Scope, now time.Time) (ed25519.PublicKey, error) {
	if err := m.Verify(authority, now); err != nil {
		return nil, err
	}
	if m.ID != s.CaseID+"-"+from || m.TenantID != Tenant || m.SubjectAgentID != from || m.Audience != "agent:"+to ||
		m.Purpose != s.purpose() || m.KeyID != from+"-authority" || m.RevocationEpoch != s.Generation || m.ExpiresAt != s.ExpiresAt || m.RequiredApprovals != 0 ||
		!reflect.DeepEqual(m.Actions, []string{Action}) || !reflect.DeepEqual(m.ResourcePrefixes, []string{resource("inbox", to, s)}) {
		return nil, errors.New("grant fields do not match the profile")
	}
	if len(m.Constraints) != 1 || m.Constraints[0].Key != DelegateKey || m.Constraints[0].Operator != "eq" || !hex64.MatchString(m.Constraints[0].Value) {
		return nil, errors.New("grant must name exactly one delegate key")
	}
	k, _ := hex.DecodeString(m.Constraints[0].Value)
	return ed25519.PublicKey(k), nil
}

type keyStoreV2 struct {
	peer     string
	s        Scope
	delegate ed25519.PublicKey
}

func (k keyStoreV2) IntentKey(_ context.Context, t, agent, id string) (ed25519.PublicKey, error) {
	if t != Tenant || agent != k.peer || id != caseKeyID(k.peer, k.s) {
		return nil, errors.New("unknown intent key")
	}
	return k.delegate, nil
}
func (k keyStoreV2) DecisionKey(_ context.Context, t, id string) (ed25519.PublicKey, error) {
	if t != Tenant || id != caseKeyID(k.peer, k.s) {
		return nil, errors.New("unknown decision key")
	}
	return k.delegate, nil
}
func (k keyStoreV2) MinimumState(_ context.Context, t string) (uint64, uint64, error) {
	if t != Tenant {
		return 0, 0, errors.New("unknown tenant")
	}
	return 1, k.s.Generation, nil
}

type ceilingV2 struct {
	self, peer string
	s          Scope
}

func (c ceilingV2) Check(_ context.Context, i decision.Intent, d decision.Decision) error {
	s := c.s
	if i.Action != Action || i.AgentID != c.peer || i.Audience != "agent:"+c.self || i.Purpose != s.purpose() || i.MandateID != s.CaseID+"-"+c.peer ||
		i.ExpiresAt > s.ExpiresAt || d.ExpiresAt > s.ExpiresAt || d.ProviderID != caseKeyID(c.peer, s) || d.RevocationEpoch != s.Generation || d.PolicyRevision != s.PolicyRevision ||
		len(d.Reasons) > 0 || len(d.Constraints) > 0 {
		return errors.New("profile ceiling rejected")
	}
	return nil
}

// proofV2 builds one v2 governed frame: proofs signed with key (normally the sender's delegate key).
type proofV2 struct {
	from, to   *party
	kind, id   string
	payload    []byte
	key        ed25519.PrivateKey
	editIntent func(*decision.Intent)
	editDec    func(*decision.Decision)
}

func (p proofV2) build() dataexchange.GovernedFrame {
	s, self, peer := scopeV2, p.from.Party, p.to.Party
	until := min(T0+proofTTL, s.ExpiresAt)
	i := decision.Intent{Version: decision.SchemaVersion, ID: p.id, TenantID: Tenant, AgentID: self, Action: Action, Resource: resource(p.kind, peer, s),
		MandateID: s.CaseID + "-" + self, Audience: "agent:" + peer, Purpose: s.purpose(), PayloadHash: dataexchange.GovernedPayloadHash(dataexchange.TypeText, "", p.payload),
		Risk: decision.RiskMedium, IssuedAt: T0, ExpiresAt: until, Nonce: nonce("v2/" + p.id), KeyID: caseKeyID(self, s)}
	if p.editIntent != nil {
		p.editIntent(&i)
	}
	if err := i.Sign(p.key); err != nil {
		panic(err)
	}
	d := decision.Decision{Version: decision.SchemaVersion, ID: "decision-" + p.id, IntentHash: must(i.Hash()), TenantID: Tenant, AgentID: self, Outcome: decision.Allow,
		PolicyRevision: s.PolicyRevision, RevocationEpoch: s.Generation, ProviderID: caseKeyID(self, s), IssuedAt: T0, ExpiresAt: until, KeyID: caseKeyID(self, s)}
	if p.editDec != nil {
		p.editDec(&d)
	}
	if err := d.Sign(p.key); err != nil {
		panic(err)
	}
	return dataexchange.GovernedFrame{Version: 1, Type: dataexchange.TypeText, Payload: append([]byte(nil), p.payload...), Intent: i, Decision: d}
}

// receiveV2 applies the stateless part of the v2 receive order. stored is the peer's grant the receiver already
// accepted for this case (nil if none).
func receiveV2(raw []byte, self string, peer Participant, s Scope, now time.Time, stored *decision.Mandate) Outcome {
	f, err := dataexchange.ReadFrame(bytes.NewReader(raw))
	if err != nil {
		return Outcome{"DENIED_FRAME", StageReadFrame, err}
	}
	if len(f.Payload) > MaxPayload || f.Type != dataexchange.TypeGoverned {
		return Outcome{"DENIED_FRAME", StageProfileFrame, errors.New("frame size or type")}
	}
	g, err := dataexchange.DecodeGovernedFrame(f)
	if err != nil {
		return Outcome{"DENIED_FRAME", StageDecodeGoverned, err}
	}
	if g.Type != dataexchange.TypeText || g.Filename != "" || g.Disclosure != nil {
		return Outcome{"DENIED_FRAME", StageProfileInner, errors.New("inner frame is not a plain text frame")}
	}
	m := resourcePattern.FindStringSubmatch(g.Intent.Resource)
	if m == nil || m[1] != self {
		return Outcome{"DENIED_RESOURCE", StageProfileResource, errors.New("resource does not name this receiver")}
	}
	kind, caseID := m[2], m[3]
	if caseID != s.CaseID {
		return Outcome{"DENIED_UNKNOWN_CASE", StageProfileResource, errors.New("unknown case")}
	}
	authority, _ := pubKey(peer.AuthorityKey)
	var delegate ed25519.PublicKey
	if kind == "invite" { // v2: the grant is checked before the proofs, because it names the proof key
		var gr decision.Mandate
		if g.Intent.ID != "invite" || strictJSON(g.Payload, &gr) != nil {
			return Outcome{"DENIED_GRANT", StagePayload, errors.New("invite payload")}
		}
		if delegate, err = verifyGrantV2(&gr, authority, peer.Party, self, s, now); err != nil {
			return Outcome{"DENIED_GRANT", StagePayload, err}
		}
		if stored != nil {
			prev, err := verifyGrantV2(stored, authority, peer.Party, self, s, now)
			if err != nil || !bytes.Equal(prev, delegate) {
				return Outcome{"DENIED_GRANT", StagePayload, errors.New("re-sent grant names another delegate key")}
			}
		}
	} else {
		if stored == nil { // the case cannot be active yet: the sender retries (PROFILE_V2_DELEGATION §5)
			return Outcome{"NOT_YET_ACTIVE", StageVerifyGoverned, errors.New("no accepted grant for this case")}
		}
		if delegate, err = verifyGrantV2(stored, authority, peer.Party, self, s, now); err != nil {
			return Outcome{"DENIED_PROOF", StageVerifyGoverned, err}
		}
	}
	v := dataexchange.DecisionFrameVerifier{
		Enforcer: &decision.Enforcer{Trust: keyStoreV2{peer.Party, s, delegate}, Ceiling: ceilingV2{self, peer.Party, s}, Now: func() time.Time { return now }},
		Resource: func(coreapi.Addr, *dataexchange.Frame) string { return resource(kind, self, s) }}
	if err := v.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, g); err != nil {
		return Outcome{"DENIED_PROOF", StageVerifyGoverned, err}
	}
	switch kind {
	case "invite":
		return Outcome{"INVITE_OK", StagePass, nil}
	case "control":
		var msg Message
		if g.Intent.ID != "revoke" || strictJSON(g.Payload, &msg) != nil || msg != (Message{Case: caseID, Generation: s.Generation, ID: "revoke", Kind: "revoke"}) {
			return Outcome{"DENIED_CONTROL", StagePayload, errors.New("control message")}
		}
		return Outcome{"CONTROL_OK", StagePass, nil}
	}
	var msg Message
	if strictJSON(g.Payload, &msg) != nil || msg.Case != caseID || msg.Generation != s.Generation || g.Intent.ID != msg.ID {
		return Outcome{"DENIED_MESSAGE", StagePayload, errors.New("message binding")}
	}
	if msg.Kind != "offer" || s.Initiator != peer.Party || !s.discloses(peer.Party, msg.Candidate) {
		return Outcome{"DENIED_MESSAGE", StagePayload, errors.New("message kind rules")}
	}
	return Outcome{"ACCEPTED", StagePass, nil}
}

// ---- v2 vectors (vectors/v2.json) ----

type V2Fixture struct {
	Description   string            `json:"description"`
	ScopeJSON     string            `json:"scope_json"`
	ScopeHash     string            `json:"scope_hash"`
	DelegateSeeds map[string]string `json:"delegate_seeds"`
	OtherCaseSeed string            `json:"other_case_delegate_seed"`
	ConstraintKey string            `json:"constraint_key"`
}

type V2Frame struct {
	FrameVec
	StoredGrant string `json:"stored_grant,omitempty"` // id of the peer grant the receiver already accepted
}

type V2 struct {
	Fixture V2Fixture   `json:"fixture"`
	Grants  []ObjectVec `json:"grants"`
	Frames  []V2Frame   `json:"frames"`
}

func buildV2() (V2, map[string]decision.Mandate) {
	s := scopeV2
	gA := grantV2(alice.authority, "alice", "bob", s, mandateIssuedAt, pub(delegateA), nil)
	gB := grantV2(bob.authority, "bob", "alice", s, mandateIssuedAt, pub(delegateB), nil)
	gAOther := grantV2(alice.authority, "alice", "bob", s, mandateIssuedAt, pub(delegateOther), nil)
	gNoDelegate := grantV2(alice.authority, "alice", "bob", s, mandateIssuedAt, pub(delegateA), func(m *decision.Mandate) { m.Constraints = nil })
	gTwo := grantV2(alice.authority, "alice", "bob", s, mandateIssuedAt, pub(delegateA), func(m *decision.Mandate) {
		m.Constraints = append(m.Constraints, decision.Constraint{Key: DelegateKey, Operator: "one_of", Value: hex.EncodeToString(pub(delegateOther))})
	})
	gBySelfDelegate := grantV2(delegateA, "alice", "bob", s, mandateIssuedAt, pub(delegateA), nil) // signed with the delegate key, not the authority key
	grants := map[string]decision.Mandate{"v2-grant-alice": gA, "v2-grant-bob": gB}
	v := V2{Fixture: V2Fixture{Description: "Profile v2 (delegated case keys). Parties and authority keys are those of fixture.json; delegate keys are per case.",
		ScopeJSON: string(s.JSON()), ScopeHash: s.Hash(), ConstraintKey: DelegateKey, OtherCaseSeed: hex.EncodeToString(delegateOther.Seed()),
		DelegateSeeds: map[string]string{"alice": hex.EncodeToString(delegateA.Seed()), "bob": hex.EncodeToString(delegateB.Seed())}},
		Grants: []ObjectVec{mandateVec("v2-grant-alice", "alice's v2 grant naming her delegate key", gA, pub(alice.authority)),
			mandateVec("v2-grant-bob", "bob's v2 grant naming his delegate key", gB, pub(bob.authority))}}
	at := T0
	frame := func(id, desc string, p proofV2, stored, code, stage string) {
		g := p.build()
		v.Frames = append(v.Frames, V2Frame{FrameVec: FrameVec{ID: id, Description: desc, Sender: p.from.Party, Receiver: p.to.Party, VerifyAt: at,
			FrameHex: hex.EncodeToString(rawFrame(g)), Envelope: string(must(json.Marshal(g))), InnerText: string(p.payload), IntentHash: must(g.Intent.Hash()),
			Expect: Expect{Accept: code == "INVITE_OK" || code == "ACCEPTED" || code == "CONTROL_OK", Code: code, Stage: stage}}, StoredGrant: stored})
	}
	inviteA := proofV2{from: alice, to: bob, kind: "invite", id: "invite", payload: must(json.Marshal(gA)), key: delegateA}
	offer := proofV2{from: alice, to: bob, kind: "inbox", id: "j1-1", payload: msgJSON(Message{Case: s.CaseID, Generation: 1, ID: "j1-1", Kind: "offer", Candidate: "s2"}), key: delegateA}
	revoke := proofV2{from: alice, to: bob, kind: "control", id: "revoke", payload: msgJSON(Message{Case: s.CaseID, Generation: 1, ID: "revoke", Kind: "revoke"}), key: delegateA}
	frame("v2-invite-alice-bob", "invite carrying alice's v2 grant, proofs signed with her delegate key", inviteA, "", "INVITE_OK", StagePass)
	frame("v2-invite-bob-alice", "invite carrying bob's v2 grant", proofV2{from: bob, to: alice, kind: "invite", id: "invite", payload: must(json.Marshal(gB)), key: delegateB}, "", "INVITE_OK", StagePass)
	frame("v2-invite-resent", "the same invite re-sent after it was accepted", inviteA, "v2-grant-alice", "INVITE_OK", StagePass)
	frame("v2-offer", "offer signed with the delegate key named in the accepted grant", offer, "v2-grant-alice", "ACCEPTED", StagePass)
	frame("v2-revoke", "revoke signed with the delegate key", revoke, "v2-grant-alice", "CONTROL_OK", StagePass)
	// negatives
	ng := func(id, desc string, p proofV2, stored, code, stage string) { frame(id, desc, p, stored, code, stage) }
	withPayload := func(p proofV2, m decision.Mandate) proofV2 { p.payload = must(json.Marshal(m)); return p }
	ng("v2-neg-grant-no-delegate", "grant without a delegate constraint", withPayload(inviteA, gNoDelegate), "", "DENIED_GRANT", StagePayload)
	ng("v2-neg-grant-two-delegates", "grant with a second delegate constraint", withPayload(inviteA, gTwo), "", "DENIED_GRANT", StagePayload)
	ng("v2-neg-grant-signed-by-delegate", "grant signed with the delegate key instead of the authority key", withPayload(inviteA, gBySelfDelegate), "", "DENIED_GRANT", StagePayload)
	ng("v2-neg-invite-other-key", "invite whose proofs are signed with a key other than the one its grant names", func() proofV2 { p := inviteA; p.key = delegateOther; return p }(), "", "DENIED_PROOF", StageVerifyGoverned)
	ng("v2-neg-resent-invite-new-key", "re-sent invite naming a different delegate key than the accepted grant", func() proofV2 {
		p := withPayload(inviteA, gAOther)
		p.key = delegateOther
		return p
	}(), "v2-grant-alice", "DENIED_GRANT", StagePayload)
	ng("v2-neg-offer-no-grant", "offer before any grant of the peer was accepted (overtook its invite): retry later", offer, "", "NOT_YET_ACTIVE", StageVerifyGoverned)
	ng("v2-neg-offer-authority-key", "offer signed with the authority key (v1 key ids)", func() proofV2 {
		p := offer
		p.key = alice.authority
		p.editIntent = func(i *decision.Intent) { i.KeyID = "alice-intent" }
		p.editDec = func(d *decision.Decision) { d.KeyID = "alice-authority"; d.ProviderID = "alice-authority" }
		return p
	}(), "v2-grant-alice", "DENIED_PROOF", StageVerifyGoverned)
	ng("v2-neg-offer-other-case-key", "offer signed with a delegate key of another case", func() proofV2 { p := offer; p.key = delegateOther; return p }(), "v2-grant-alice", "DENIED_PROOF", StageVerifyGoverned)
	ng("v2-neg-offer-v1-provider", "offer whose decision provider id is the v1 value", func() proofV2 {
		p := offer
		p.editDec = func(d *decision.Decision) { d.ProviderID = "alice-authority" }
		return p
	}(), "v2-grant-alice", "DENIED_PROOF", StageVerifyGoverned)
	return v, grants
}

func checkV2(v V2) error {
	at := time.Unix(T0, 0)
	for _, o := range v.Grants {
		if err := checkObject(o, at); err != nil {
			return fmt.Errorf("%s: %w", o.ID, err)
		}
	}
	grants := map[string]*decision.Mandate{}
	for _, o := range v.Grants {
		var m decision.Mandate
		if err := strictJSON([]byte(o.JSON), &m); err != nil {
			return fmt.Errorf("%s: %w", o.ID, err)
		}
		grants[o.ID] = &m
	}
	parties := map[string]*party{"alice": alice, "bob": bob}
	for _, f := range v.Frames {
		raw, err := hex.DecodeString(f.FrameHex)
		if err != nil {
			return fmt.Errorf("%s: %w", f.ID, err)
		}
		var stored *decision.Mandate
		if f.StoredGrant != "" {
			if stored = grants[f.StoredGrant]; stored == nil {
				return fmt.Errorf("%s: unknown stored grant %s", f.ID, f.StoredGrant)
			}
		}
		got := receiveV2(raw, f.Receiver, parties[f.Sender].Participant, scopeV2, time.Unix(f.VerifyAt, 0), stored)
		if got.Code != f.Expect.Code || got.Stage != f.Expect.Stage {
			return fmt.Errorf("%s: got %s at %s (%v), want %s at %s", f.ID, got.Code, got.Stage, got.Err, f.Expect.Code, f.Expect.Stage)
		}
	}
	return nil
}
