package main

import (
	"bytes"
	"encoding/binary"
	"net/url"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestFleetGatewayReconnectDelayIsBoundedAndExponential(t *testing.T) {
	policy:=controlplane.FleetGatewayTransportPolicyModel()
	previous:=time.Duration(0)
	for failures:=1;failures<=20;failures++{
		delay:=fleetGatewayReconnectDelay(policy,failures,"cluster-a")
		if delay<time.Duration(policy.ReconnectMinSeconds)*time.Second||delay>time.Duration(policy.ReconnectMaxSeconds)*time.Second{t.Fatalf("failures=%d delay=%s",failures,delay)}
		if delay<previous{t.Fatalf("reconnect delay regressed: previous=%s current=%s",previous,delay)}
		previous=delay
	}
}

func TestFleetGatewayClientFramesAreMasked(t *testing.T){
	payload:=[]byte(`{"type":"heartbeat","epoch":7}`)
	var out bytes.Buffer
	if err:=writeFleetGatewayClientFrame(&out,0x1,payload);err!=nil{t.Fatal(err)}
	raw:=out.Bytes()
	if len(raw)<6||raw[1]&0x80==0{t.Fatalf("client frame is not masked: %x",raw)}
	offset:=2
	length:=int(raw[1]&0x7f)
	if length==126{length=int(binary.BigEndian.Uint16(raw[2:4]));offset=4}
	mask:=raw[offset:offset+4];masked:=raw[offset+4:]
	if len(masked)!=length{t.Fatalf("masked payload len=%d want=%d",len(masked),length)}
	got:=make([]byte,len(masked));for i,b:=range masked{got[i]=b^mask[i%4]}
	if !bytes.Equal(got,payload){t.Fatalf("payload=%q",got)}
}

func TestFleetGatewayServerFramesRejectMasking(t *testing.T){
	frame:=[]byte{0x81,0x81,1,2,3,4,byte('x')^1}
	if _,_,err:=readFleetGatewayServerFrame(bytes.NewReader(frame));err==nil{t.Fatal("masked server frame was accepted")}
}

func TestFleetGatewayStreamURLRequiresTLSAndCarriesNoGatewayOwnerClaim(t *testing.T){
	if _,err:=fleetGatewayStreamURL("http://hub.example","cluster-a","session-a",2);err==nil{t.Fatal("plaintext gateway URL accepted")}
	raw,err:=fleetGatewayStreamURL("https://hub.example","cluster-a","session-a",2);if err!=nil{t.Fatal(err)}
	u,err:=url.Parse(raw);if err!=nil{t.Fatal(err)}
	if u.Query().Get("sessionId")!="session-a"||u.Query().Get("epoch")!="2"{t.Fatalf("query=%s",u.RawQuery)}
	if u.Query().Get("gatewayInstanceId")!=""{t.Fatalf("agent was allowed to claim gateway owner: %s",u.RawQuery)}
}
