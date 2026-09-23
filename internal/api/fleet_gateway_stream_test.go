package api

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func maskedFleetGatewayFrame(opcode byte, payload []byte, mask [4]byte) []byte {
	var out bytes.Buffer
	out.WriteByte(0x80 | opcode)
	if len(payload) < 126 {
		out.WriteByte(0x80 | byte(len(payload)))
	} else {
		out.WriteByte(0x80 | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(payload)))
		out.Write(ext[:])
	}
	out.Write(mask[:])
	for i, b := range payload {
		out.WriteByte(b ^ mask[i%4])
	}
	return out.Bytes()
}

func TestFleetGatewayWebSocketAcceptMatchesRFC6455(t *testing.T) {
	got := fleetGatewayWebSocketAccept("dGhlIHNhbXBsZSBub25jZQ==")
	if got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("accept=%q", got)
	}
}

func TestFleetGatewayFrameReadsMaskedHeartbeat(t *testing.T) {
	payload := []byte(`{"type":"heartbeat","epoch":7}`)
	frame := maskedFleetGatewayFrame(0x1, payload, [4]byte{1, 2, 3, 4})
	opcode, got, err := readFleetGatewayFrame(bufio.NewReader(bytes.NewReader(frame)))
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 0x1 || string(got) != string(payload) {
		t.Fatalf("opcode=%d payload=%q", opcode, got)
	}
}

func TestFleetGatewayFrameRejectsUnmaskedAndOversizedClientFrames(t *testing.T) {
	unmasked := []byte{0x81, 0x01, 'x'}
	if _, _, err := readFleetGatewayFrame(bufio.NewReader(bytes.NewReader(unmasked))); err == nil || !strings.Contains(err.Error(), "masked") {
		t.Fatalf("unmasked frame err=%v", err)
	}
	var oversized bytes.Buffer
	oversized.WriteByte(0x81)
	oversized.WriteByte(0x80 | 126)
	var ext [2]byte
	binary.BigEndian.PutUint16(ext[:], fleetGatewayMaxFrameBytes+1)
	oversized.Write(ext[:])
	oversized.Write([]byte{1, 2, 3, 4})
	if _, _, err := readFleetGatewayFrame(bufio.NewReader(bytes.NewReader(oversized.Bytes()))); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized frame err=%v", err)
	}
}
