package guardian

// Experimental in-process orchestration; no HTTP endpoint or normative grant.
import (
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "strings"
 "time"
)
type Flow struct {
 IntentConfig Config
 AttestationKey ed25519.PublicKey
 Challenges *Challenges
 Issuer GrantIssuer
 VerifyEvidence EvidenceVerifier
}
type FlowSession struct {
 Intent VerifiedIntent
 Request GrantRequest
 Challenge Challenge
}
func (f *Flow) Begin(signedIntent []byte, resourceAudience string)(FlowSession,error){
 if f==nil||f.Challenges==nil||f.Issuer.ID==""||resourceAudience==""{return FlowSession{},ErrDenied}
 decision,err:=Evaluate(signedIntent,f.IntentConfig);if err!=nil||!decision.Allowed{return FlowSession{},ErrDenied}
 var m struct{MessageID string `json:"message_id"`;Issuer string `json:"issuer"`;Audience string `json:"audience"`;Intent struct{Action string `json:"action"`;Resource string `json:"resource"`} `json:"intent"`}
 if json.Unmarshal(signedIntent,&m)!=nil||m.MessageID==""{return FlowSession{},ErrDenied}
 var raw map[string]any
 if json.Unmarshal(signedIntent,&raw)!=nil{return FlowSession{},ErrDenied}
 binding:=map[string]any{"issuer":raw["issuer"],"audience":raw["audience"],"intent":raw["intent"],"dimensions":raw["dimensions"]}
 digest,err:=BindingDigest(binding);if err!=nil{return FlowSession{},ErrDenied}
 verified:=VerifiedIntent{ID:m.MessageID,Issuer:m.Issuer,Audience:m.Audience,Digest:digest}
 challenge,err:=f.Challenges.Issue(verified);if err!=nil{return FlowSession{},err}
 return FlowSession{Intent:verified,Challenge:challenge,Request:GrantRequest{Subject:m.Issuer,Audience:resourceAudience,IntentDigest:digest,Action:m.Intent.Action,Resource:m.Intent.Resource}},nil
}
func(f *Flow) Finish(session FlowSession,signedAttestation []byte)(SignedGrant,error){
 if f==nil||f.Challenges==nil||f.VerifyEvidence==nil||f.IntentConfig.Now==nil||len(f.AttestationKey)!=ed25519.PublicKeySize{return SignedGrant{},ErrDenied}
 if verifyAttestationSignature(signedAttestation,f.AttestationKey)!=nil{return SignedGrant{},ErrDenied}
 var m struct {
  LipVersion string `json:"lip_version"`
  MessageType string `json:"message_type"`
  InReplyTo string `json:"in_reply_to"`
  Issuer string `json:"issuer"`
  Audience string `json:"audience"`
  Nonce string `json:"nonce"`
  IssuedAt string `json:"issued_at"`
  ExpiresAt string `json:"expires_at"`
  Intent map[string]any `json:"intent"`
  Dimensions map[string]any `json:"dimensions"`
  Evidence []json.RawMessage `json:"evidence"`
 }
 if json.Unmarshal(signedAttestation,&m)!=nil||m.LipVersion!="0.3"||m.MessageType!="attestation"||m.Issuer!=session.Intent.Issuer||m.Audience!=session.Intent.Audience||m.Intent==nil||m.Dimensions==nil||len(m.Evidence)==0{return SignedGrant{},ErrDenied}
 issued,err:=time.Parse(time.RFC3339Nano,m.IssuedAt);if err!=nil{return SignedGrant{},ErrDenied}
 expiry,err:=time.Parse(time.RFC3339Nano,m.ExpiresAt)
 if err!=nil||!expiry.After(issued)||expiry.Sub(issued)>10*time.Minute||!f.IntentConfig.Now().Before(expiry){return SignedGrant{},ErrDenied}
 digest,err:=BindingDigest(map[string]any{"issuer":m.Issuer,"audience":m.Audience,"intent":m.Intent,"dimensions":m.Dimensions})
 if err!=nil||!EqualDigest(digest,session.Intent.Digest){return SignedGrant{},ErrDenied}
 evidenceBytes,err:=json.Marshal(m.Evidence);if err!=nil{return SignedGrant{},ErrDenied}
 att:=VerifiedAttestation{InReplyTo:m.InReplyTo,Issuer:m.Issuer,Audience:m.Audience,Digest:digest,Nonce:m.Nonce,Evidence:evidenceBytes}
 if err:=f.Challenges.Consume(session.Challenge.ID,att,f.VerifyEvidence);err!=nil{return SignedGrant{},err}
 return f.Issuer.Issue(true,session.Request)
}
func verifyAttestationSignature(raw []byte,pub ed25519.PublicKey)error{
 if len(raw)==0||len(raw)>65536||len(pub)!=ed25519.PublicKeySize||strictShape(raw)!=nil{return ErrDenied}
 var m map[string]json.RawMessage
 if json.Unmarshal(raw,&m)!=nil{return ErrDenied}
 var proof struct{Type string `json:"type"`;JWS string `json:"jws"`}
 if json.Unmarshal(m["proof"],&proof)!=nil||proof.Type!="jws-detached"{return ErrDenied}
 parts:=strings.Split(proof.JWS,".");if len(parts)!=3||parts[1]!=""{return ErrDenied}
 hb,err:=base64.RawURLEncoding.DecodeString(parts[0]);if err!=nil{return ErrDenied}
 var h struct{Alg string `json:"alg"`;Typ string `json:"typ"`;Kid string `json:"kid"`}
 if json.Unmarshal(hb,&h)!=nil||h.Alg!="EdDSA"||h.Typ!="application/lip+json"||h.Kid==""{return ErrDenied}
 sig,err:=base64.RawURLEncoding.DecodeString(parts[2]);if err!=nil{return ErrDenied}
 delete(m,"proof")
 payload,err:=canonicalSubset(m);if err!=nil{return ErrDenied}
 input:=parts[0]+"."+base64.RawURLEncoding.EncodeToString(payload)
 if !ed25519.Verify(pub,[]byte(input),sig){return errors.New("invalid attestation signature")}
 return nil
}
