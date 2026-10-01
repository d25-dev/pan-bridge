// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// This file reproduces the Agent Network Client's wire profile (pan-client
// internal/app: scope.go, wire.go) on top of the Pilot packages, with a fixed
// clock instead of time.Now and without the stateful (database) checks.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/dataexchange"
)

const (
	Tenant      = "anv-client-m1"
	TemplateID  = "finite-choice-v1"
	PurposeCode = "schedule"
	MaxPerSide  = 32
	MaxPayload  = 16384
	FrameCap    = 65536
	proofTTL    = 60
	Action      = "data.send.text"
)

// The Client refuses to start unless the Pilot frame cap is 64 KiB; the
// generator pins the same value instead of reading PILOT_DATAEXCHANGE_MAX_FRAME.
func init() { dataexchange.MaxFrameSize = FrameCap }

var (
	idPattern       = regexp.MustCompile(`^[a-z0-9-]{1,48}$`)
	resourcePattern = regexp.MustCompile(`^agent:([A-Za-z0-9-]{1,32})/(inbox|invite|control)/([a-z0-9-]{8,48})/g1$`)
)

type Participant struct {
	Party        string `json:"party"`
	Addr         string `json:"addr"`
	TransportKey string `json:"transport_key"`
	IntentKey    string `json:"intent_key"`
	AuthorityKey string `json:"authority_key"`
}

type Scope struct {
	SchemaVersion      int                 `json:"schema_version"`
	CaseID             string              `json:"case_id"`
	Generation         uint64              `json:"generation"`
	TemplateID         string              `json:"template_id"`
	PurposeCode        string              `json:"purpose_code"`
	Initiator          string              `json:"initiator"`
	Participants       []Participant       `json:"participants"`
	Catalog            map[string]string   `json:"catalog"`
	Disclosure         map[string][]string `json:"disclosure_by_party"`
	Actions            []string            `json:"actions"`
	MaxMessagesPerSide int                 `json:"max_messages_per_side"`
	MaxPayload         int                 `json:"max_payload"`
	ExpiresAt          int64               `json:"expires_at"`
	PolicyRevision     uint64              `json:"policy_revision"`
}

type Message struct {
	Case       string
	Generation uint64
	ID         string
	Kind       string
	Candidate  string
	Digest     string `json:",omitempty"`
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (s Scope) JSON() []byte    { b, _ := json.Marshal(s); return b }
func (s Scope) Hash() string    { return sum(s.JSON()) }
func (s Scope) purpose() string { return PurposeCode + ":" + s.Hash() }
func (s Scope) party(p string) (Participant, bool) {
	for _, x := range s.Participants {
		if x.Party == p {
			return x, true
		}
	}
	return Participant{}, false
}
func (s Scope) discloses(party, candidate string) bool {
	return slices.Contains(s.Disclosure[party], candidate)
}

func resource(kind, to string, s Scope) string {
	return fmt.Sprintf("agent:%s/%s/%s/g%d", to, kind, s.CaseID, s.Generation)
}

func resultDigest(s Scope, candidate string) string {
	return sum([]byte(fmt.Sprintf("anv-result-v1|%s|%d|%s|%s", s.CaseID, s.Generation, s.Hash(), candidate)))
}

// strictJSON accepts b only if it is exactly json.Marshal of the decoded value.
func strictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing data")
	}
	if c, err := json.Marshal(v); err != nil || !bytes.Equal(c, b) {
		return errors.New("not the canonical JSON encoding")
	}
	return nil
}

func pubKey(h string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("bad public key")
	}
	return b, nil
}

// grant is the Client's Mandate for (self -> peer, scope).
func grant(authority ed25519.PrivateKey, self, peer string, s Scope, issuedAt int64) (decision.Mandate, error) {
	m := decision.Mandate{Version: decision.SchemaVersion, ID: s.CaseID + "-" + self, TenantID: Tenant, SubjectAgentID: self, Actions: []string{Action},
		ResourcePrefixes: []string{resource("inbox", peer, s)}, Audience: "agent:" + peer, Purpose: s.purpose(), RevocationEpoch: s.Generation,
		IssuedAt: issuedAt, ExpiresAt: s.ExpiresAt, KeyID: self + "-authority"}
	return m, m.Sign(authority)
}

// verifyGrant is the Client's exact-grant check; it reports which part failed.
func verifyGrant(m *decision.Mandate, key ed25519.PublicKey, from, to string, s Scope, now time.Time) error {
	if err := m.Verify(key, now); err != nil {
		return err
	}
	if m.ID != s.CaseID+"-"+from || m.TenantID != Tenant || m.SubjectAgentID != from || m.Audience != "agent:"+to ||
		m.Purpose != s.purpose() || m.KeyID != from+"-authority" || m.RevocationEpoch != s.Generation || m.ExpiresAt != s.ExpiresAt || m.RequiredApprovals != 0 ||
		len(m.Constraints) != 0 || !reflect.DeepEqual(m.Actions, []string{Action}) || !reflect.DeepEqual(m.ResourcePrefixes, []string{resource("inbox", to, s)}) {
		return errors.New("grant fields do not match the profile")
	}
	return nil
}

type keyStore struct {
	peer Participant
	gen  uint64
}

func (k keyStore) IntentKey(_ context.Context, t, agent, id string) (ed25519.PublicKey, error) {
	if t != Tenant || agent != k.peer.Party || id != agent+"-intent" {
		return nil, errors.New("unknown intent key")
	}
	return pubKey(k.peer.IntentKey)
}
func (k keyStore) DecisionKey(_ context.Context, t, id string) (ed25519.PublicKey, error) {
	if t != Tenant || id != k.peer.Party+"-authority" {
		return nil, errors.New("unknown decision key")
	}
	return pubKey(k.peer.AuthorityKey)
}
func (k keyStore) MinimumState(_ context.Context, t string) (uint64, uint64, error) {
	if t != Tenant {
		return 0, 0, errors.New("unknown tenant")
	}
	return 1, k.gen, nil
}

type ceiling struct {
	self, peer string
	scope      Scope
}

func (c ceiling) Check(_ context.Context, i decision.Intent, d decision.Decision) error {
	s := c.scope
	if i.Action != Action || i.AgentID != c.peer || i.Audience != "agent:"+c.self || i.Purpose != s.purpose() || i.MandateID != s.CaseID+"-"+c.peer ||
		i.ExpiresAt > s.ExpiresAt || d.ExpiresAt > s.ExpiresAt || d.ProviderID != c.peer+"-authority" || d.RevocationEpoch != s.Generation || d.PolicyRevision != s.PolicyRevision ||
		len(d.Reasons) > 0 || len(d.Constraints) > 0 {
		return errors.New("profile ceiling rejected")
	}
	return nil
}

// Stages of the receive order, in the order they are applied.
const (
	StageReadFrame       = "read_frame"
	StageProfileFrame    = "profile_frame"
	StageDecodeGoverned  = "decode_governed"
	StageProfileInner    = "profile_inner"
	StageProfileResource = "profile_resource"
	StageVerifyGoverned  = "verify_governed"
	StagePayload         = "profile_payload"
	StagePass            = "pass"
)

type Outcome struct {
	Code, Stage string
	Err         error
}

// receive applies the stateless part of the Client's receive order to raw
// stream bytes sent by peer to self. It assumes the transport peer is peer
// and that the case exists, is active, and has no earlier messages.
func receive(raw []byte, self string, peer Participant, s Scope, now time.Time) Outcome {
	f, err := dataexchange.ReadFrame(bytes.NewReader(raw))
	if err != nil {
		return Outcome{"DENIED_FRAME", StageReadFrame, err}
	}
	if len(f.Payload) > MaxPayload {
		return Outcome{"DENIED_FRAME", StageProfileFrame, fmt.Errorf("envelope %d bytes exceeds %d", len(f.Payload), MaxPayload)}
	}
	if f.Type != dataexchange.TypeGoverned {
		return Outcome{"DENIED_FRAME", StageProfileFrame, fmt.Errorf("frame type %d is not governed", f.Type)}
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
	v := dataexchange.DecisionFrameVerifier{
		Enforcer: &decision.Enforcer{Trust: keyStore{peer, s.Generation}, Ceiling: ceiling{self, peer.Party, s}, Now: func() time.Time { return now }},
		Resource: func(coreapi.Addr, *dataexchange.Frame) string { return resource(kind, self, s) }}
	if err := v.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, g); err != nil {
		return Outcome{"DENIED_PROOF", StageVerifyGoverned, err}
	}
	switch kind {
	case "invite":
		var gr decision.Mandate
		if g.Intent.ID != "invite" {
			return Outcome{"DENIED_GRANT", StagePayload, errors.New("invite intent id")}
		}
		if err := strictJSON(g.Payload, &gr); err != nil {
			return Outcome{"DENIED_GRANT", StagePayload, err}
		}
		pk, _ := pubKey(peer.AuthorityKey)
		if err := verifyGrant(&gr, pk, peer.Party, self, s, now); err != nil {
			return Outcome{"DENIED_GRANT", StagePayload, err}
		}
		return Outcome{"INVITE_OK", StagePass, nil}
	case "control":
		var msg Message
		if g.Intent.ID != "revoke" || strictJSON(g.Payload, &msg) != nil || msg != (Message{Case: caseID, Generation: s.Generation, ID: "revoke", Kind: "revoke"}) {
			return Outcome{"DENIED_CONTROL", StagePayload, errors.New("control message")}
		}
		return Outcome{"CONTROL_OK", StagePass, nil}
	}
	var msg Message
	if err := strictJSON(g.Payload, &msg); err != nil {
		return Outcome{"DENIED_MESSAGE", StagePayload, err}
	}
	if msg.Case != caseID || msg.Generation != s.Generation || !idPattern.MatchString(msg.ID) || g.Intent.ID != msg.ID {
		return Outcome{"DENIED_MESSAGE", StagePayload, errors.New("message binding")}
	}
	ok := false
	switch msg.Kind {
	case "offer":
		ok = s.Initiator == peer.Party && msg.Digest == "" && s.discloses(peer.Party, msg.Candidate)
	case "result":
		ok = s.Initiator != peer.Party && s.discloses(peer.Party, msg.Candidate) && s.discloses(self, msg.Candidate) && msg.Digest == resultDigest(s, msg.Candidate)
	case "confirm_result":
		ok = s.Initiator == peer.Party && msg.Digest == resultDigest(s, msg.Candidate)
	}
	if !ok {
		return Outcome{"DENIED_MESSAGE", StagePayload, errors.New("message kind rules")}
	}
	return Outcome{"ACCEPTED", StagePass, nil}
}
