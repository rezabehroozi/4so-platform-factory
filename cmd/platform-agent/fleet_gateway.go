package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const fleetGatewayClientMaxFrameBytes = 4096

type fleetGatewayHead struct {
	Authority   string                            `json:"authority"`
	LatestEpoch int64                             `json:"latestEpoch"`
	Session     *controlplane.FleetGatewaySession `json:"session,omitempty"`
}

type fleetGatewayClientMessage struct {
	Type  string `json:"type"`
	Epoch int64  `json:"epoch"`
}

type fleetGatewayFrame struct {
	opcode  byte
	payload []byte
}

type fleetGatewayDuplex interface {
	io.ReadCloser
	io.Writer
}

func fleetGatewaySessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "fgw-" + hex.EncodeToString(raw[:]), nil
}

func fleetGatewayReconnectDelay(policy controlplane.FleetGatewayTransportPolicy, failures int, clusterID string) time.Duration {
	minimum := time.Duration(policy.ReconnectMinSeconds) * time.Second
	maximum := time.Duration(policy.ReconnectMaxSeconds) * time.Second
	if minimum <= 0 {
		minimum = time.Second
	}
	if maximum < minimum {
		maximum = minimum
	}
	if failures < 1 {
		failures = 1
	}
	delay := minimum
	for i := 1; i < failures && delay < maximum; i++ {
		if delay > maximum/2 {
			delay = maximum
			break
		}
		delay *= 2
	}
	if delay > maximum {
		delay = maximum
	}
	if delay < maximum {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", strings.TrimSpace(clusterID), failures)))
		window := delay / 5
		if window > 0 {
			jitter := time.Duration(binary.BigEndian.Uint16(sum[:2])) * window / 65535
			delay += jitter
			if delay > maximum {
				delay = maximum
			}
		}
	}
	return delay
}

func (a *agent) fleetGatewaySessionHead(ctx context.Context) (fleetGatewayHead, error) {
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + url.PathEscape(a.clusterID) + "/gateway-session-head"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fleetGatewayHead{}, err
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return fleetGatewayHead{}, err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fleetGatewayHead{}, fmt.Errorf("gateway session head %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	var out fleetGatewayHead
	if err = json.NewDecoder(res.Body).Decode(&out); err != nil {
		return fleetGatewayHead{}, err
	}
	if out.Authority != controlplane.FleetAgentGatewaySessionAuthority || out.LatestEpoch < 0 {
		return fleetGatewayHead{}, fmt.Errorf("gateway session head authority is invalid")
	}
	if out.Session != nil && out.Session.Epoch != out.LatestEpoch {
		return fleetGatewayHead{}, fmt.Errorf("gateway session head epoch contradicts returned session")
	}
	return out, nil
}

func fleetGatewayStreamURL(hub, clusterID, sessionID string, epoch int64) (string, error) {
	u, err := url.Parse(strings.TrimSpace(hub))
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(u.Scheme, "https") || strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("fleet gateway requires an https hub for WSS transport")
	}
	if strings.TrimSpace(clusterID) == "" || strings.TrimSpace(sessionID) == "" || epoch <= 0 {
		return "", fmt.Errorf("fleet gateway session identity is incomplete")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/agent/v1/clusters/" + url.PathEscape(clusterID) + "/gateway-stream"
	q := u.Query()
	q.Set("sessionId", sessionID)
	q.Set("epoch", strconv.FormatInt(epoch, 10))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func fleetGatewayClientAccept(key string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(key) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeFleetGatewayClientFrame(w io.Writer, opcode byte, payload []byte) error {
	if len(payload) > fleetGatewayClientMaxFrameBytes {
		return fmt.Errorf("fleet gateway client frame exceeds limit")
	}
	var header []byte
	switch {
	case len(payload) < 126:
		header = []byte{0x80 | opcode, 0x80 | byte(len(payload))}
	case len(payload) <= 65535:
		header = make([]byte, 4)
		header[0] = 0x80 | opcode
		header[1] = 0x80 | 126
		binary.BigEndian.PutUint16(header[2:], uint16(len(payload)))
	default:
		return fmt.Errorf("fleet gateway client frame exceeds encodable limit")
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(mask[:]); err != nil {
		return err
	}
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	_, err := w.Write(masked)
	return err
}

func readFleetGatewayServerFrame(r io.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	if header[0]&0x80 == 0 {
		return 0, nil, fmt.Errorf("fragmented gateway websocket frames are not supported")
	}
	if header[1]&0x80 != 0 {
		return 0, nil, fmt.Errorf("server gateway websocket frames must not be masked")
	}
	opcode := header[0] & 0x0f
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if opcode >= 0x8 && length > 125 {
		return 0, nil, fmt.Errorf("gateway websocket control frame is too large")
	}
	if length > fleetGatewayClientMaxFrameBytes {
		return 0, nil, fmt.Errorf("gateway websocket frame exceeds client limit")
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}

func (a *agent) openFleetGatewayStream(ctx context.Context, sessionID string, epoch int64) (fleetGatewayDuplex, error) {
	endpoint, err := fleetGatewayStreamURL(a.cfg.Hub, a.clusterID, sessionID, epoch)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", key)

	transport, ok := a.hub.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("hub transport does not support persistent gateway streams")
	}
	streamTransport := transport.Clone()
	streamTransport.ForceAttemptHTTP2 = false
	client := &http.Client{Transport: streamTransport}
	res, err := client.Do(req)
	if err != nil {
		streamTransport.CloseIdleConnections()
		return nil, err
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		defer res.Body.Close()
		streamTransport.CloseIdleConnections()
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("gateway websocket upgrade %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	if !strings.EqualFold(strings.TrimSpace(res.Header.Get("Upgrade")), "websocket") || !strings.Contains(strings.ToLower(res.Header.Get("Connection")), "upgrade") {
		res.Body.Close()
		streamTransport.CloseIdleConnections()
		return nil, fmt.Errorf("gateway websocket upgrade response is incomplete")
	}
	if strings.TrimSpace(res.Header.Get("Sec-WebSocket-Accept")) != fleetGatewayClientAccept(key) {
		res.Body.Close()
		streamTransport.CloseIdleConnections()
		return nil, fmt.Errorf("gateway websocket accept identity mismatch")
	}
	stream, ok := res.Body.(fleetGatewayDuplex)
	if !ok {
		res.Body.Close()
		streamTransport.CloseIdleConnections()
		return nil, fmt.Errorf("gateway websocket response is not duplex")
	}
	return stream, nil
}

func (a *agent) runFleetGatewaySession(ctx context.Context, sessionID string, epoch int64) (bool, error) {
	stream, err := a.openFleetGatewayStream(ctx, sessionID, epoch)
	if err != nil {
		return false, err
	}
	defer stream.Close()

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	frames := make(chan fleetGatewayFrame, 8)
	readErrors := make(chan error, 1)
	go func() {
		for {
			opcode, payload, readErr := readFleetGatewayServerFrame(stream)
			if readErr != nil {
				select {
				case readErrors <- readErr:
				case <-sessionCtx.Done():
				}
				return
			}
			select {
			case frames <- fleetGatewayFrame{opcode: opcode, payload: payload}:
			case <-sessionCtx.Done():
				return
			}
		}
	}()

	policy := controlplane.FleetGatewayTransportPolicyModel()
	heartbeatEvery := time.Duration(policy.HeartbeatSeconds) * time.Second
	if heartbeatEvery <= 0 {
		heartbeatEvery = 30 * time.Second
	}
	ackDeadline := time.Duration(policy.SessionStaleSeconds) * time.Second / 2
	if ackDeadline < 2*heartbeatEvery {
		ackDeadline = 2 * heartbeatEvery
	}
	heartbeat, _ := json.Marshal(fleetGatewayClientMessage{Type: "heartbeat", Epoch: epoch})
	if err = writeFleetGatewayClientFrame(stream, 0x1, heartbeat); err != nil {
		return true, err
	}
	ticker := time.NewTicker(heartbeatEvery)
	defer ticker.Stop()
	ackTimer := time.NewTimer(ackDeadline)
	defer ackTimer.Stop()
	resetAckTimer := func() {
		if !ackTimer.Stop() {
			select {
			case <-ackTimer.C:
			default:
			}
		}
		ackTimer.Reset(ackDeadline)
	}

	for {
		select {
		case <-ctx.Done():
			_ = writeFleetGatewayClientFrame(stream, 0x8, []byte("agent shutdown"))
			return true, ctx.Err()
		case <-ticker.C:
			if err = writeFleetGatewayClientFrame(stream, 0x1, heartbeat); err != nil {
				return true, err
			}
		case <-ackTimer.C:
			return true, fmt.Errorf("gateway heartbeat acknowledgement timed out")
		case readErr := <-readErrors:
			if ctx.Err() != nil {
				return true, ctx.Err()
			}
			return true, readErr
		case frame := <-frames:
			switch frame.opcode {
			case 0x1:
				var message fleetGatewayClientMessage
				if err = json.Unmarshal(frame.payload, &message); err != nil || message.Type != "heartbeat-ack" || message.Epoch != epoch {
					return true, fmt.Errorf("gateway returned an invalid heartbeat acknowledgement")
				}
				resetAckTimer()
			case 0x8:
				_ = writeFleetGatewayClientFrame(stream, 0x8, frame.payload)
				return true, fmt.Errorf("gateway requested stream close")
			case 0x9:
				if err = writeFleetGatewayClientFrame(stream, 0xA, frame.payload); err != nil {
					return true, err
				}
			case 0xA:
				resetAckTimer()
			default:
				return true, fmt.Errorf("gateway returned unsupported websocket opcode %d", frame.opcode)
			}
		}
	}
}

func (a *agent) runFleetGateway(ctx context.Context) {
	policy := controlplane.FleetGatewayTransportPolicyModel()
	failures := 0
	for ctx.Err() == nil {
		head, err := a.fleetGatewaySessionHead(ctx)
		established := false
		if err == nil {
			const maxInt64 = int64(1<<63 - 1)
			if head.LatestEpoch == maxInt64 {
				err = errors.New("fleet gateway session epoch exhausted")
			} else {
				sessionID, idErr := fleetGatewaySessionID()
				if idErr != nil {
					err = idErr
				} else {
					established, err = a.runFleetGatewaySession(ctx, sessionID, head.LatestEpoch+1)
				}
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil && a.log != nil {
			a.log.Warn("fleet gateway stream disconnected", "error", err, "authority", controlplane.FleetAgentGatewaySessionAuthority)
		}
		if established {
			failures = 0
		}
		failures++
		delay := fleetGatewayReconnectDelay(policy, failures, a.clusterID)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}
