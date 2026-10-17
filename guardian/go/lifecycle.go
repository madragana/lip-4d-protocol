package guardian

// Experimental challenge state machine. This is NOT a network endpoint or
// authorisation-grant issuer. Callers must cryptographically authenticate
// the intent and attestation before calling these methods.
import (
 "crypto/rand"
 "encoding/base64"
 "errors"
 "sync"
 "time"
)

var (
 ErrChallengeInvalid = errors.New("challenge invalid, expired, mismatched or already consumed")
 ErrEvidenceDenied = errors.New("independent evidence verifier denied attestation")
)
// VerifiedIntent must be constructed ONLY after signature, identity and
// semantic validation by a trusted adapter.
type VerifiedIntent struct {
 ID, Issuer, Audience, Digest string
}
// VerifiedAttestation must be constructed ONLY after independent signature
// and identity validation by a trusted adapter.
type VerifiedAttestation struct {
 InReplyTo, Issuer, Audience, Digest, Nonce string
 Evidence []byte
}
type Challenge struct {
 ID string `json:"challenge_id"`
 InReplyTo string `json:"in_reply_to"`
 Nonce string `json:"nonce"`
 ExpiresAt time.Time `json:"expires_at"`
}
type EvidenceVerifier func(intent VerifiedIntent, att VerifiedAttestation) error
type pendingChallenge struct {
 intent VerifiedIntent
 challenge Challenge
}
// Challenges is an in-memory, single-process experimental store. It does not
// survive restarts or coordinate across instances.
type Challenges struct {
 mu sync.Mutex
 pending map[string]pendingChallenge
 now func() time.Time
 ttl time.Duration
}
func NewChallenges(now func()time.Time, ttl time.Duration)(*Challenges,error){
 if now==nil||ttl<=0||ttl>5*time.Minute{return nil,errors.New("invalid challenge configuration")}
 return &Challenges{pending:make(map[string]pendingChallenge),now:now,ttl:ttl},nil
}
func randomToken() (string,error){
 var b [24]byte
 if _,err:=rand.Read(b[:]);err!=nil{return "",err}
 return base64.RawURLEncoding.EncodeToString(b[:]),nil
}
func (s *Challenges) Issue(intent VerifiedIntent)(Challenge,error){
 if intent.ID==""||intent.Issuer==""||intent.Audience==""||intent.Digest==""{return Challenge{},ErrChallengeInvalid}
 id,err:=randomToken();if err!=nil{return Challenge{},err}
 nonce,err:=randomToken();if err!=nil{return Challenge{},err}
 s.mu.Lock()
 defer s.mu.Unlock()
 // Reject repeated outstanding requests for the same authenticated intent.
 for _,v:=range s.pending{
  if v.intent.ID==intent.ID && v.intent.Issuer==intent.Issuer{return Challenge{},ErrChallengeInvalid}
 }
 ch:=Challenge{ID:"urn:lip4d:challenge:"+id,InReplyTo:intent.ID,Nonce:nonce,ExpiresAt:s.now().Add(s.ttl)}
 s.pending[ch.ID]=pendingChallenge{intent:intent,challenge:ch}
 return ch,nil
}
// Consume atomically claims and destroys challenge state BEFORE evaluating
// evidence. Failure never restores it: retries need a new challenge.
func (s *Challenges) Consume(id string, att VerifiedAttestation, verify EvidenceVerifier) error {
 if verify==nil{return ErrEvidenceDenied}
 s.mu.Lock()
 state,found:=s.pending[id]
 if found {delete(s.pending,id)}
 now:=s.now()
 s.mu.Unlock()
 if !found||!now.Before(state.challenge.ExpiresAt){return ErrChallengeInvalid}
 if att.InReplyTo!=state.challenge.ID ||
    att.Nonce!=state.challenge.Nonce ||
    att.Issuer!=state.intent.Issuer ||
    att.Audience!=state.intent.Audience ||
    att.Digest!=state.intent.Digest {return ErrChallengeInvalid}
 if err:=verify(state.intent,att);err!=nil{return ErrEvidenceDenied}
 // A successful challenge response is NOT a grant. A separate trusted
 // policy engine must decide whether to issue an independently signed grant.
 return nil
}
