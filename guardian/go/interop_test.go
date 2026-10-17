package guardian

import (
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
 "time"
)
type interoperabilityFixture struct {
 PublicKey string `json:"public_key_raw_base64url"`
 Message map[string]any `json:"message"`
}
func interopFixture(t *testing.T)(map[string]any,Config) {
 t.Helper()
 data,err:=os.ReadFile(filepath.Join("..","..","test-vectors","python-go-intent-ed25519.json"));if err!=nil{t.Fatal(err)}
 var v interoperabilityFixture
 if err:=json.Unmarshal(data,&v);err!=nil{t.Fatal(err)}
 pub,err:=base64.RawURLEncoding.DecodeString(v.PublicKey);if err!=nil{t.Fatal(err)}
 cfg:=Config{TrustedIssuer:"spiffe://example.org/agent/a", Audience:"https://guardian.example.org",PublicKey:ed25519.PublicKey(pub),
 AllowedActions:map[string]bool{"org.example.read":true},AllowedResourcePrefix:"https://api.example.org/",Now:func()time.Time{return time.Date(2026,10,17,20,1,0,0,time.UTC)}}
 return v.Message,cfg
}
func evaluateInterop(t *testing.T, m map[string]any,c Config) bool {
 t.Helper()
 raw,err:=json.Marshal(m);if err!=nil{t.Fatal(err)}
 d,err:=Evaluate(raw,c)
 return err==nil && d.Allowed
}
func TestPythonSignatureVerifiesInGo(t *testing.T){
 m,c:=interopFixture(t)
 if !evaluateInterop(t,m,c){t.Fatal("Python-signed fixture must verify in Go within limited JSON profile")}
}
func TestPythonFixtureTamperingFails(t *testing.T){
 for _,field:=range []string{"issuer","audience","intent","dimensions","proof"}{
  m,c:=interopFixture(t)
  switch field {
  case "issuer":m[field]="spiffe://example.org/agent/other"
  case "audience":m[field]="https://other.example.org"
  case "intent":m["intent"].(map[string]any)["purpose"]="malicious purpose"
  case "dimensions":m["dimensions"].(map[string]any)["logos"].(map[string]any)["rationale"]="modified"
  case "proof":m["proof"].(map[string]any)["jws"]="bad"
  }
  if evaluateInterop(t,m,c){t.Fatalf("accepted modified %s",field)}
 }
}
func TestPythonFixturePolicyFailsClosed(t *testing.T){
 m,c:=interopFixture(t)
 c.AllowedActions=map[string]bool{}
 if evaluateInterop(t,m,c){t.Fatal("missing action permission must deny")}
}
