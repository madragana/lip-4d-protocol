package guardian

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "testing"
 "time"
)
func signed(t *testing.T,m map[string]any,key ed25519.PrivateKey)[]byte{
 t.Helper()
 h:=base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"demo","typ":"application/lip+json"}`))
 p,_:=json.Marshal(m)
 s:=ed25519.Sign(key,[]byte(h+"."+base64.RawURLEncoding.EncodeToString(p)))
 m["proof"]=map[string]any{"type":"jws-detached","jws":h+".."+base64.RawURLEncoding.EncodeToString(s)}
 b,_:=json.Marshal(m);return b
}
func prepare(t *testing.T)(*Flow,[]byte,ed25519.PrivateKey){
 t.Helper()
 pub,priv,_:=ed25519.GenerateKey(rand.Reader)
 _,grantKey,_:=ed25519.GenerateKey(rand.Reader)
 now:=time.Date(2026,10,17,20,1,0,0,time.UTC)
 clock:=func()time.Time{return now}
 store,_:=NewChallenges(clock,time.Minute)
 f:=&Flow{IntentConfig:Config{TrustedIssuer:"spiffe://example.org/agent/a",Audience:"https://guardian.example.org",PublicKey:pub,AllowedActions:map[string]bool{"org.example.read":true},AllowedResourcePrefix:"https://api.example.org/",Now:clock},AttestationKey:pub,Challenges:store,Issuer:GrantIssuer{ID:"https://guardian.example.org",Key:grantKey,Now:clock,TTL:time.Minute},VerifyEvidence:func(_ VerifiedIntent,a VerifiedAttestation)error{if len(a.Evidence)==0{return errors.New("missing evidence")};return nil}}
 b,err:=os.ReadFile(filepath.Join("..","..","test-vectors","python-go-intent-ed25519.json"));if err!=nil{t.Fatal(err)}
 var v struct{Message map[string]any `json:"message"`}
 if json.Unmarshal(b,&v)!=nil{t.Fatal("invalid fixture")}
 delete(v.Message,"proof")
 return f,signed(t,v.Message,priv),priv
}
func attestation(t *testing.T,s FlowSession,key ed25519.PrivateKey)[]byte{
 t.Helper()
 b,err:=os.ReadFile(filepath.Join("..","..","test-vectors","python-go-intent-ed25519.json"));if err!=nil{t.Fatal(err)}
 var v struct{Message map[string]any `json:"message"`}
 if json.Unmarshal(b,&v)!=nil{t.Fatal("invalid fixture")}
 m:=map[string]any{"lip_version":"0.3","message_type":"attestation","message_id":"urn:uuid:cccccccc-cccc-4ccc-8ccc-cccccccccccc","in_reply_to":s.Challenge.ID,"issuer":s.Intent.Issuer,"audience":s.Intent.Audience,"nonce":s.Challenge.Nonce,"issued_at":"2026-10-17T20:01:00Z","expires_at":"2026-10-17T20:02:00Z","intent":v.Message["intent"],"dimensions":v.Message["dimensions"],"evidence":[]any{map[string]any{"type":"test","format":"json","value":map[string]any{"ok":true}}}}
 return signed(t,m,key)
}
func TestFullFlowAndGrantReplay(t *testing.T){
 f,m,k:=prepare(t)
 s,err:=f.Begin(m,"https://api.example.org");if err!=nil{t.Fatal(err)}
 grant,err:=f.Finish(s,attestation(t,s,k));if err!=nil{t.Fatal(err)}
 gate,err:=NewGrantGate(f.Issuer.ID,f.Issuer.Key.Public().(ed25519.PublicKey),f.IntentConfig.Now);if err!=nil{t.Fatal(err)}
 req:=Invocation(s.Request)
 if err:=gate.Authorize(grant,req);err!=nil{t.Fatal(err)}
 if gate.Authorize(grant,req)==nil{t.Fatal("replay accepted")}
}
func TestInvalidSignatureAndAttestationReplay(t *testing.T){
 f,m,k:=prepare(t)
 s,err:=f.Begin(m,"https://api.example.org");if err!=nil{t.Fatal(err)}
 good:=attestation(t,s,k)
 var tampered map[string]any
 if json.Unmarshal(good,&tampered)!=nil{t.Fatal("decode")}
 tampered["nonce"]="wrong"
 bad,_:=json.Marshal(tampered)
 if _,err:=f.Finish(s,bad);err==nil{t.Fatal("signature tamper accepted")}
 if _,err:=f.Finish(s,good);err!=nil{t.Fatal(err)}
 if _,err:=f.Finish(s,good);err==nil{t.Fatal("replay accepted")}
}
func TestEvidenceDenial(t *testing.T){
 f,m,k:=prepare(t)
 f.VerifyEvidence=func(VerifiedIntent,VerifiedAttestation)error{return errors.New("denied")}
 s,err:=f.Begin(m,"https://api.example.org");if err!=nil{t.Fatal(err)}
 good:=attestation(t,s,k)
 if _,err:=f.Finish(s,good);err==nil{t.Fatal("failed evidence accepted")}
 if _,err:=f.Finish(s,good);err==nil{t.Fatal("denied evidence replay accepted")}
}
