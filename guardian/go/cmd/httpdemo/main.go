// Command httpdemo runs a localhost-only experimental Guardian and resource gate.
package main

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "log"
 "net"
 "net/http"
 "sync"
 "time"

 guardian "github.com/madragana/lip-4d-protocol/guardian/go"
)
type server struct {
 flow *guardian.Flow
 gate *guardian.GrantGate
 mu sync.Mutex
 sessions map[string]guardian.FlowSession
}
func (s *server) begin(w http.ResponseWriter,r *http.Request){
 if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
 raw,err:=io.ReadAll(http.MaxBytesReader(w,r.Body,65536));if err!=nil{http.Error(w,"invalid request",400);return}
 session,err:=s.flow.Begin(raw,"https://api.example.org")
 if err!=nil{http.Error(w,"intent denied",403);return}
 s.mu.Lock();s.sessions[session.Challenge.ID]=session;s.mu.Unlock()
 write(w,session.Challenge)
}
func (s *server) finish(w http.ResponseWriter,r *http.Request){
 if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
 var input struct{ChallengeID string `json:"challenge_id"`;Attestation json.RawMessage `json:"attestation"`}
 if err:=json.NewDecoder(http.MaxBytesReader(w,r.Body,65536)).Decode(&input);err!=nil{http.Error(w,"invalid request",400);return}
 s.mu.Lock();session,found:=s.sessions[input.ChallengeID];if found{delete(s.sessions,input.ChallengeID)};s.mu.Unlock()
 if !found{http.Error(w,"unknown or consumed challenge",403);return}
 token,err:=s.flow.Finish(session,input.Attestation)
 if err!=nil{http.Error(w,"attestation denied",403);return}
 write(w,token)
}
func (s *server) invoke(w http.ResponseWriter,r *http.Request){
 if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
 var input struct{Grant guardian.SignedGrant `json:"grant"`;Request guardian.Invocation `json:"request"`}
 if err:=json.NewDecoder(http.MaxBytesReader(w,r.Body,65536)).Decode(&input);err!=nil{http.Error(w,"invalid request",400);return}
 if s.gate.Authorize(input.Grant,input.Request)!=nil{http.Error(w,"access denied",403);return}
 write(w,map[string]any{"result":"protected example operation executed"})
}
func write(w http.ResponseWriter,v any){w.Header().Set("Content-Type","application/json");_ = json.NewEncoder(w).Encode(v)}
func main(){
 var keyText string
 flag.StringVar(&keyText,"agent-key","","base64url Ed25519 agent public key (required)")
 flag.Parse()
 agentKey,err:=base64.RawURLEncoding.DecodeString(keyText)
 if err!=nil||len(agentKey)!=ed25519.PublicKeySize{log.Fatal("valid --agent-key required")}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{log.Fatal(err)}
 clock:=time.Now
 challenges,err:=guardian.NewChallenges(clock,time.Minute);if err!=nil{log.Fatal(err)}
 const issuer="https://guardian.example.org"
 flow:=&guardian.Flow{
 IntentConfig:guardian.Config{TrustedIssuer:"spiffe://example.org/agent/a",Audience:issuer,PublicKey:ed25519.PublicKey(agentKey),AllowedActions:map[string]bool{"org.example.read":true},AllowedResourcePrefix:"https://api.example.org/",Now:clock},
 AttestationKey:ed25519.PublicKey(agentKey),Challenges:challenges,
 Issuer:guardian.GrantIssuer{ID:issuer,Key:priv,Now:clock,TTL:time.Minute},
 // DEMO ONLY: accepts example evidence, not independently trustworthy evidence.
 VerifyEvidence:func(_ guardian.VerifiedIntent,a guardian.VerifiedAttestation)error{
  var descriptors []struct{Type string `json:"type"`;Format string `json:"format"`}
  if json.Unmarshal(a.Evidence,&descriptors)!=nil||len(descriptors)!=1||descriptors[0].Type!="demo"||descriptors[0].Format!="json" {return fmt.Errorf("evidence denied")}
  return nil
 },
 }
 gate,err:=guardian.NewGrantGate(issuer,pub,clock);if err!=nil{log.Fatal(err)}
 s:=&server{flow:flow,gate:gate,sessions:make(map[string]guardian.FlowSession)}
 gl,err:=net.Listen("tcp","127.0.0.1:8765");if err!=nil{log.Fatal(err)}
 rl,err:=net.Listen("tcp","127.0.0.1:8766");if err!=nil{log.Fatal(err)}
 g:=http.NewServeMux();g.HandleFunc("/begin",s.begin);g.HandleFunc("/finish",s.finish)
 p:=http.NewServeMux();p.HandleFunc("/invoke",s.invoke)
 go func(){log.Fatal(http.Serve(rl,p))}()
 log.Println("DEMO ONLY Guardian 127.0.0.1:8765, protected resource 127.0.0.1:8766")
 log.Fatal(http.Serve(gl,g))
}
