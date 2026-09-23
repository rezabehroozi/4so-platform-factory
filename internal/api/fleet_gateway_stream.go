package api

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const fleetGatewayWebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
const fleetGatewayMaxFrameBytes = 4096

type fleetGatewayStreamMessage struct {
	Type  string `json:"type"`
	Epoch int64  `json:"epoch"`
}

func fleetGatewayWebSocketAccept(key string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(key) + fleetGatewayWebSocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func validateFleetGatewayUpgrade(r *http.Request) (string, error) {
	if r == nil {
		return "", errors.New("request is required")
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return "", errors.New("websocket upgrade is required")
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return "", errors.New("connection upgrade token is required")
	}
	if strings.TrimSpace(r.Header.Get("Sec-WebSocket-Version")) != "13" {
		return "", errors.New("websocket version 13 is required")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 16 {
		return "", errors.New("valid websocket key is required")
	}
	return key, nil
}

func readFleetGatewayFrame(r *bufio.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	if header[0]&0x80 == 0 {
		return 0, nil, errors.New("fragmented websocket frames are not supported")
	}
	opcode := header[0] & 0x0f
	if header[1]&0x80 == 0 {
		return 0, nil, errors.New("client websocket frames must be masked")
	}
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
		return 0, nil, errors.New("websocket control frame is too large")
	}
	if length > fleetGatewayMaxFrameBytes {
		return 0, nil, errors.New("websocket frame exceeds gateway limit")
	}
	var mask [4]byte
	if _, err := io.ReadFull(r, mask[:]); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return opcode, payload, nil
}

func writeFleetGatewayFrame(w *bufio.ReadWriter, opcode byte, payload []byte) error {
	if len(payload) > fleetGatewayMaxFrameBytes {
		return errors.New("gateway websocket frame exceeds limit")
	}
	if err := w.WriteByte(0x80 | opcode); err != nil {
		return err
	}
	if len(payload) < 126 {
		if err := w.WriteByte(byte(len(payload))); err != nil {
			return err
		}
	} else {
		if err := w.WriteByte(126); err != nil {
			return err
		}
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(payload)))
		if _, err := w.Write(ext[:]); err != nil {
			return err
		}
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return w.Flush()
}

func (s *Server) fleetGatewayStream(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	cert, err := s.mtlsAgentCertificate(r, clusterID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_MTLS_REQUIRED", err.Error())
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), clusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	key, err := validateFleetGatewayUpgrade(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "FLEET_GATEWAY_WEBSOCKET_REQUIRED", err.Error())
		return
	}
	sessionID := strings.TrimSpace(r.URL.Query().Get("sessionId"))
	epoch, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("epoch")), 10, 64)
	if err != nil || epoch <= 0 || sessionID == "" {
		writeError(w, http.StatusBadRequest, "FLEET_GATEWAY_SESSION_IDENTITY_REQUIRED", "sessionId and positive epoch are required")
		return
	}
	gatewayInstanceID, err := fleetGatewayInstanceIdentity()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "FLEET_GATEWAY_INSTANCE_ID_UNAVAILABLE", err.Error())
		return
	}
	store, ok := s.fleetGatewaySessionStore()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "FLEET_GATEWAY_SESSION_STORE_UNAVAILABLE", "fleet gateway session authority is unavailable")
		return
	}
	admission, err := store.AdmitFleetGatewaySession(r.Context(), controlplane.FleetGatewaySessionRequest{
		SessionID: sessionID, ClusterID: cluster.ID, ExternalUID: cluster.ExternalUID,
		CertificateID: cert.ID, CertificateFingerprint: cert.Fingerprint, Epoch: epoch,
		Transport: "wss", TargetInitiated: true, MutualTLS: true, GatewayInstanceID: gatewayInstanceID,
	}, time.Now().UTC(), "cluster-agent-gateway")
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if admission.Decision == controlplane.FleetGatewayAdmissionReject {
		writeJSON(w, http.StatusConflict, admission)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "FLEET_GATEWAY_HIJACK_UNAVAILABLE", "HTTP server does not support websocket hijacking")
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	defer func() {
		_, _ = store.CloseFleetGatewaySession(r.Context(), cluster.ID, sessionID, epoch, cert.ID, time.Now().UTC())
	}()
	if _, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", fleetGatewayWebSocketAccept(key)); err != nil {
		return
	}
	if err = rw.Flush(); err != nil {
		return
	}
	policy := controlplane.FleetGatewayTransportPolicyModel()
	resetDeadline := func() {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(policy.SessionStaleSeconds) * time.Second))
	}
	resetDeadline()
	for {
		opcode, payload, readErr := readFleetGatewayFrame(rw.Reader)
		if readErr != nil {
			return
		}
		switch opcode {
		case 0x1:
			var message fleetGatewayStreamMessage
			if err := json.Unmarshal(payload, &message); err != nil || message.Type != "heartbeat" || message.Epoch != epoch {
				_ = writeFleetGatewayFrame(rw, 0x8, []byte("invalid heartbeat"))
				return
			}
			session, err := store.HeartbeatFleetGatewaySession(r.Context(), cluster.ID, sessionID, epoch, cert.ID, time.Now().UTC())
			if err != nil {
				_ = writeFleetGatewayFrame(rw, 0x8, []byte("session fenced"))
				return
			}
			resetDeadline()
			ack, _ := json.Marshal(fleetGatewayStreamMessage{Type: "heartbeat-ack", Epoch: session.Epoch})
			if err := writeFleetGatewayFrame(rw, 0x1, ack); err != nil {
				return
			}
		case 0x8:
			_ = writeFleetGatewayFrame(rw, 0x8, payload)
			return
		case 0x9:
			if err := writeFleetGatewayFrame(rw, 0xA, payload); err != nil {
				return
			}
		case 0xA:
			resetDeadline()
		default:
			_ = writeFleetGatewayFrame(rw, 0x8, []byte("unsupported frame"))
			return
		}
	}
}
