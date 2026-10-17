package guardian
import ("testing";"crypto/ed25519";"crypto/rand";"encoding/base64";"encoding/json";"time")
func TestRejectUnsignedIntent(t *testing.T){
 pub,_,_:=ed25519.GenerateKey(rand.Reader)
 msg:=map[string]any{"lip_version":"0.3","message_type":"intent","issuer":"spiffe://example.org/agent/a","audience":"https://guardian.example.org","issued_at":"2026-10-17T21:00:00Z","expires_at":"2026-10-17T21:01:00Z","intent":map[string]any{"action":"read","resource":"https://api.example.org/record/1","purpose":"test"},"dimensions":map[string]any{"chronos":map[string]any{},"logos":map[string]any{},"topos":map[string]any{},"physis":map[string]any{}}}
 raw,_:=json.Marshal(msg)
 cfg:=Config{TrustedIssuer:"spiffe://example.org/agent/a",Audience:"https://guardian.example.org",PublicKey:pub,Now:func()time.Time{return time.Date(2026,10,17,21,0,30,0,time.UTC)},AllowedActions:map[string]bool{"read":true},AllowedResourcePrefix:"https://api.example.org/"}
 d,err:=Evaluate(raw,cfg);if err==nil||d.Allowed{t.Fatal("accepted unsigned intent")}
}
func TestDigest(t *testing.T){
 a,e:=BindingDigest(map[string]any{"a":"b"});if e!=nil{t.Fatal(e)}
 if !EqualDigest(a,a)||EqualDigest(a,a+"x"){t.Fatal("bad digest comparison")}
 if _,e:=base64.RawURLEncoding.DecodeString(a[8:]);e!=nil{t.Fatal(e)}
}
func TestDuplicateKeysDenied(t *testing.T){if strictShape([]byte(`{"a":1,"a":2}`))==nil{t.Fatal("duplicate member accepted")}}
