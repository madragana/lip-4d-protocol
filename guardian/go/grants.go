package guardian

// Experimental local signed-grant profile. NOT yet a wire-compatible
// LIP-4D v0.3 grant/JWS implementation. No live service is exposed.
import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "errors"
 "strings"
 "sync"
 "time"
)
var ErrGrantDenied=errors.New("grant denied")
type GrantClaims struct {
 Version string `json:"lip_version"`
 Status string `json:"status"`
 ID string `json:"grant_id"`
 Issuer string `json:"issuer"`
 Subject string `json:"subject"`
 Audience string `json:"audience"`
 IntentDigest string `json:"intent_digest"`
 Action string `json:"action"`
 Resource string `json:"resource"`
 IssuedAt int64 `json:"issued_at_unix"`
 ExpiresAt int64 `json:"expires_at_unix"`
 MaxUses int `json:"max_uses"`
}
type SignedGrant struct {
 Claims GrantClaims `json:"claims"`
 Signature string `json:"signature"`
}
type GrantRequest struct {
 Subject,Audience,IntentDigest,Action,Resource string
}
type GrantIssuer struct {
 ID string
 Key ed25519.PrivateKey
 Now func()time.Time
 TTL time.Duration
}
func (s GrantIssuer) Issue(approved bool,r GrantRequest)(SignedGrant,error){
 if !approved||len(s.Key)!=ed25519.PrivateKeySize||s.ID==""||s.Now==nil||s.TTL<=0||s.TTL>5*time.Minute||
 r.Subject==""||r.Audience==""||r.Action==""||r.Resource==""||!validDigest(r.IntentDigest){return SignedGrant{},ErrGrantDenied}
 var entropy [24]byte
 if _,err:=rand.Read(entropy[:]);err!=nil{return SignedGrant{},err}
 now:=s.Now().UTC()
 claims:=GrantClaims{Version:"0.3",Status:"granted",ID:"urn:lip4d:grant:"+base64.RawURLEncoding.EncodeToString(entropy[:]),Issuer:s.ID,
 Subject:r.Subject,Audience:r.Audience,IntentDigest:r.IntentDigest,Action:r.Action,Resource:r.Resource,
 IssuedAt:now.Unix(),ExpiresAt:now.Add(s.TTL).Unix(),MaxUses:1}
 if claims.ExpiresAt<=claims.IssuedAt{return SignedGrant{},ErrGrantDenied}
 payload,err:=json.Marshal(claims);if err!=nil{return SignedGrant{},err}
 return SignedGrant{Claims:claims,Signature:base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.Key,payload))},nil
}
func validDigest(value string)bool {
 if !strings.HasPrefix(value,"sha-256:") {return false}
 raw,err:=base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value,"sha-256:"))
 return err==nil && len(raw)==32 && "sha-256:"+base64.RawURLEncoding.EncodeToString(raw)==value
}
type Invocation struct{Subject,Audience,IntentDigest,Action,Resource string}
// GrantGate is single-process replay protection; persistent/distributed state
// is required for any deployment.
type GrantGate struct {
 mu sync.Mutex
 used map[string]bool
 Now func()time.Time
 TrustedIssuer string
 PublicKey ed25519.PublicKey
}
func NewGrantGate(issuer string,key ed25519.PublicKey,clock func()time.Time)(*GrantGate,error){
 if issuer==""||len(key)!=ed25519.PublicKeySize||clock==nil{return nil,ErrGrantDenied}
 return &GrantGate{used:make(map[string]bool),Now:clock,TrustedIssuer:issuer,PublicKey:append(ed25519.PublicKey(nil),key...)},nil
}
// Authorize consumes an exactly matching, authenticated grant before returning
// success. A successful return is the ONLY local permission to execute.
func (g *GrantGate) Authorize(token SignedGrant,request Invocation)error{
 if g==nil{return ErrGrantDenied}
 c:=token.Claims
 if c.Version!="0.3"||c.Status!="granted"||c.ID==""||c.Issuer!=g.TrustedIssuer||c.MaxUses!=1||
 !validDigest(c.IntentDigest)||c.Subject==""||c.Audience==""||c.Action==""||c.Resource=="" {return ErrGrantDenied}
 now:=g.Now().Unix()
 if c.ExpiresAt<=now||c.IssuedAt>now+30||c.ExpiresAt<=c.IssuedAt||c.ExpiresAt-c.IssuedAt>300{return ErrGrantDenied}
 if request.Subject!=c.Subject||request.Audience!=c.Audience||request.IntentDigest!=c.IntentDigest||
 request.Action!=c.Action||request.Resource!=c.Resource{return ErrGrantDenied}
 sig,err:=base64.RawURLEncoding.DecodeString(token.Signature)
 if err!=nil||len(sig)!=ed25519.SignatureSize{return ErrGrantDenied}
 payload,err:=json.Marshal(c)
 if err!=nil||!ed25519.Verify(g.PublicKey,payload,sig){return ErrGrantDenied}
 g.mu.Lock()
 defer g.mu.Unlock()
 if g.used[c.ID]{return ErrGrantDenied}
 g.used[c.ID]=true
 return nil
}
