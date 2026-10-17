package guardian

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "sync"
 "testing"
 "time"
)
func grantFixture(t *testing.T)(SignedGrant,*GrantGate,Invocation,*time.Time){
 t.Helper()
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Date(2026,10,17,20,0,0,0,time.UTC)
 clock:=func()time.Time{return now}
 digest:="sha-256:"+base64.RawURLEncoding.EncodeToString(make([]byte,32))
 request:=GrantRequest{Subject:"spiffe://example.org/agent/a",Audience:"https://api.example.org",IntentDigest:digest,Action:"read",Resource:"https://api.example.org/items/1"}
 issuer:=GrantIssuer{ID:"https://guardian.example.org",Key:priv,Now:clock,TTL:time.Minute}
 token,err:=issuer.Issue(true,request);if err!=nil{t.Fatal(err)}
 gate,err:=NewGrantGate(issuer.ID,pub,clock);if err!=nil{t.Fatal(err)}
 return token,gate,Invocation(request),&now
}
func TestGrantAllowsOnce(t *testing.T){
 token,gate,req,_:=grantFixture(t)
 if err:=gate.Authorize(token,req);err!=nil{t.Fatal(err)}
 if err:=gate.Authorize(token,req);err==nil{t.Fatal("replay accepted")}
}
func TestGrantRejectsTampering(t *testing.T){
 for _,field:=range []string{"action","resource","audience","subject","intent","signature","issuer","expiry"}{
  token,gate,req,_:=grantFixture(t)
  switch field {
  case "action":token.Claims.Action="write"
  case "resource":token.Claims.Resource="https://api.example.org/items/2"
  case "audience":token.Claims.Audience="https://elsewhere.example.org"
  case "subject":token.Claims.Subject="attacker"
  case "intent":token.Claims.IntentDigest="sha-256:"+base64.RawURLEncoding.EncodeToString(make([]byte,32))[:42]+"X"
  case "signature":token.Signature="bad"
  case "issuer":token.Claims.Issuer="wrong"
  case "expiry":token.Claims.ExpiresAt=token.Claims.IssuedAt+999
  }
  if gate.Authorize(token,req)==nil{t.Fatalf("accepted tampered %s",field)}
 }
}
func TestGrantRejectsWrongInvocation(t *testing.T){
 for _,change:=range []func(*Invocation){
  func(r *Invocation){r.Action="write"},func(r *Invocation){r.Resource+="/other"},
  func(r *Invocation){r.Audience="elsewhere"},func(r *Invocation){r.Subject="other"},
  func(r *Invocation){r.IntentDigest="invalid"},
 }{
  token,gate,req,_:=grantFixture(t);change(&req)
  if gate.Authorize(token,req)==nil{t.Fatal("accepted mismatch")}
 }
}
func TestGrantExpires(t *testing.T){
 token,gate,req,now:=grantFixture(t)
 *now=now.Add(61*time.Second)
 if gate.Authorize(token,req)==nil{t.Fatal("expired grant accepted")}
}
func TestGrantDeniedByPolicy(t *testing.T){
 _,priv,_:=ed25519.GenerateKey(rand.Reader)
 issuer:=GrantIssuer{ID:"guardian",Key:priv,Now:time.Now,TTL:time.Minute}
 if _,err:=issuer.Issue(false,GrantRequest{});err==nil{t.Fatal("policy denial bypassed")}
}
func TestGrantConcurrentUse(t *testing.T){
 token,gate,req,_:=grantFixture(t)
 var wg sync.WaitGroup
 accepted:=make(chan bool,32)
 for i:=0;i<32;i++{wg.Add(1);go func(){defer wg.Done();accepted<-gate.Authorize(token,req)==nil}()}
 wg.Wait();close(accepted)
 n:=0;for ok:=range accepted{if ok{n++}}
 if n!=1{t.Fatalf("expected one authorisation, got %d",n)}
}
