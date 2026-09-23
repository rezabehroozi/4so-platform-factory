package persistence

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const fleetGatewaySessionColumns = `session_id,cluster_id,external_uid,certificate_id,certificate_fingerprint,epoch,state,gateway_instance_id,connected_at,last_heartbeat_at,drain_requested_at,closed_at`

type fleetGatewaySessionScanner interface{ Scan(...any) error }

func scanFleetGatewaySession(row fleetGatewaySessionScanner) (controlplane.FleetGatewaySession, error) {
	var v controlplane.FleetGatewaySession
	err := row.Scan(&v.SessionID,&v.ClusterID,&v.ExternalUID,&v.CertificateID,&v.CertificateFingerprint,&v.Epoch,&v.State,&v.GatewayInstanceID,&v.ConnectedAt,&v.LastHeartbeatAt,&v.DrainRequestedAt,&v.ClosedAt)
	return v, err
}

func (s *PostgresStore) GetFleetGatewaySession(ctx context.Context, sessionID string) (controlplane.FleetGatewaySession, error) {
	v, err := scanFleetGatewaySession(s.db.QueryRowContext(ctx, `SELECT `+fleetGatewaySessionColumns+` FROM fleet_gateway_sessions WHERE session_id=$1`, strings.TrimSpace(sessionID)))
	return v, mapDBError(err)
}

func (s *PostgresStore) GetCurrentFleetGatewaySession(ctx context.Context, clusterID string) (controlplane.FleetGatewaySession, error) {
	v, err := scanFleetGatewaySession(s.db.QueryRowContext(ctx, `SELECT `+fleetGatewaySessionColumns+` FROM fleet_gateway_sessions WHERE cluster_id=$1 AND state IN ('ACTIVE','DRAINING') ORDER BY epoch DESC LIMIT 1`, strings.TrimSpace(clusterID)))
	return v, mapDBError(err)
}

func (s *PostgresStore) GetLatestFleetGatewaySession(ctx context.Context, clusterID string) (controlplane.FleetGatewaySession, error) {
	v, err := scanFleetGatewaySession(s.db.QueryRowContext(ctx, `SELECT `+fleetGatewaySessionColumns+` FROM fleet_gateway_sessions WHERE cluster_id=$1 ORDER BY epoch DESC LIMIT 1`, strings.TrimSpace(clusterID)))
	return v, mapDBError(err)
}

func (s *PostgresStore) AdmitFleetGatewaySession(ctx context.Context, req controlplane.FleetGatewaySessionRequest, at time.Time, actor string) (controlplane.FleetGatewaySessionAdmission, error) {
	cluster, err := s.GetManagedCluster(ctx, req.ClusterID)
	if err != nil { return controlplane.FleetGatewaySessionAdmission{}, err }
	cert, err := s.GetAgentCertificate(ctx, req.CertificateID)
	if err != nil { return controlplane.FleetGatewaySessionAdmission{}, err }
	at = at.UTC()
	var out controlplane.FleetGatewaySessionAdmission
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		var current *controlplane.FleetGatewaySession
		row := tx.QueryRowContext(ctx, `SELECT `+fleetGatewaySessionColumns+` FROM fleet_gateway_sessions WHERE cluster_id=$1 AND state IN ('ACTIVE','DRAINING') ORDER BY epoch DESC LIMIT 1 FOR UPDATE`, cluster.ID)
		existing, scanErr := scanFleetGatewaySession(row)
		if scanErr == nil {
			current = &existing
		} else if !errors.Is(scanErr, sql.ErrNoRows) {
			return mapDBError(scanErr)
		}
		latestEpoch := int64(0)
		latestRow := tx.QueryRowContext(ctx, `SELECT `+fleetGatewaySessionColumns+` FROM fleet_gateway_sessions WHERE cluster_id=$1 ORDER BY epoch DESC LIMIT 1 FOR UPDATE`, cluster.ID)
		latest, latestErr := scanFleetGatewaySession(latestRow)
		if latestErr == nil {
			latestEpoch = latest.Epoch
		} else if !errors.Is(latestErr, sql.ErrNoRows) {
			return mapDBError(latestErr)
		}
		admission, evalErr := controlplane.AdmitFleetGatewaySessionWithLatestEpoch(cluster, cert, req, current, latestEpoch, at)
		if evalErr != nil { return evalErr }
		out = admission
		if admission.Decision == controlplane.FleetGatewayAdmissionReject || admission.Decision == controlplane.FleetGatewayAdmissionReplay {
			return nil
		}
		if current != nil && admission.Decision == controlplane.FleetGatewayAdmissionReplaceStale {
			closed, closeErr := controlplane.CloseFleetGatewaySession(*current, at)
			if closeErr != nil { return closeErr }
			if _, e := tx.ExecContext(ctx, `UPDATE fleet_gateway_sessions SET state='CLOSED',closed_at=$2 WHERE session_id=$1 AND state='ACTIVE'`, closed.SessionID, at); e != nil { return mapDBError(e) }
		}
		if admission.Session == nil { return fmt.Errorf("%w: admitted fleet session is empty", controlplane.ErrValidation) }
		v := *admission.Session
		if _, e := tx.ExecContext(ctx, `INSERT INTO fleet_gateway_sessions(session_id,cluster_id,external_uid,certificate_id,certificate_fingerprint,epoch,state,gateway_instance_id,connected_at,last_heartbeat_at,drain_requested_at,closed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,v.SessionID,v.ClusterID,v.ExternalUID,v.CertificateID,v.CertificateFingerprint,v.Epoch,v.State,v.GatewayInstanceID,v.ConnectedAt,v.LastHeartbeatAt,v.DrainRequestedAt,v.ClosedAt); e != nil { return mapDBError(e) }
		action := "fleet_gateway_session.admitted"
		if admission.Decision == controlplane.FleetGatewayAdmissionReplaceStale { action = "fleet_gateway_session.replaced_stale" }
		if e := s.appendAuditTx(ctx,tx,actor,action,"fleetGatewaySession",v.SessionID,v.Epoch,"",map[string]any{"projectId":cluster.ProjectID,"clusterId":cluster.ID,"certificateId":cert.ID,"epoch":v.Epoch,"gatewayInstanceId":v.GatewayInstanceID}); e != nil { return e }
		return s.appendOutboxTx(ctx,tx,"fleetGatewaySession",v.SessionID,action,v)
	})
	return out, err
}

func (s *PostgresStore) HeartbeatFleetGatewaySession(ctx context.Context, clusterID, sessionID string, epoch int64, certificateID string, at time.Time) (controlplane.FleetGatewaySession, error) {
	at = at.UTC()
	var out controlplane.FleetGatewaySession
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanFleetGatewaySession(tx.QueryRowContext(ctx,`SELECT `+fleetGatewaySessionColumns+` FROM fleet_gateway_sessions WHERE session_id=$1 FOR UPDATE`,strings.TrimSpace(sessionID)))
		if e != nil { return mapDBError(e) }
		if v.ClusterID != strings.TrimSpace(clusterID) || v.CertificateID != strings.TrimSpace(certificateID) { return controlplane.ErrNotFound }
		next, e := controlplane.HeartbeatFleetGatewaySession(v, sessionID, epoch, at); if e != nil { return e }
		if _, e = tx.ExecContext(ctx,`UPDATE fleet_gateway_sessions SET last_heartbeat_at=$2 WHERE session_id=$1`,next.SessionID,next.LastHeartbeatAt); e != nil { return mapDBError(e) }
		out = next
		return nil
	})
	return out, err
}

func (s *PostgresStore) DrainFleetGatewaySession(ctx context.Context, clusterID string, expectedEpoch int64, actor string, at time.Time) (controlplane.FleetGatewaySession, error) {
	at=at.UTC()
	cluster,err:=s.GetManagedCluster(ctx,clusterID);if err!=nil{return controlplane.FleetGatewaySession{},err}
	var out controlplane.FleetGatewaySession
	err=s.serializable(ctx,func(tx *sql.Tx)error{
		v,e:=scanFleetGatewaySession(tx.QueryRowContext(ctx,`SELECT `+fleetGatewaySessionColumns+` FROM fleet_gateway_sessions WHERE cluster_id=$1 AND state='ACTIVE' ORDER BY epoch DESC LIMIT 1 FOR UPDATE`,cluster.ID));if e!=nil{return mapDBError(e)}
		if v.Epoch!=expectedEpoch{return controlplane.ErrConflict}
		next,e:=controlplane.DrainFleetGatewaySession(v,at);if e!=nil{return e}
		if _,e=tx.ExecContext(ctx,`UPDATE fleet_gateway_sessions SET state='DRAINING',drain_requested_at=$2 WHERE session_id=$1`,next.SessionID,at);e!=nil{return mapDBError(e)}
		if e=s.appendAuditTx(ctx,tx,actor,"fleet_gateway_session.drain_requested","fleetGatewaySession",next.SessionID,next.Epoch,"",map[string]any{"projectId":cluster.ProjectID,"clusterId":cluster.ID,"epoch":next.Epoch});e!=nil{return e}
		if e=s.appendOutboxTx(ctx,tx,"fleetGatewaySession",next.SessionID,"fleet_gateway_session.drain_requested",next);e!=nil{return e}
		out=next;return nil
	})
	return out,err
}

func (s *PostgresStore) CloseFleetGatewaySession(ctx context.Context, clusterID, sessionID string, epoch int64, certificateID string, at time.Time) (controlplane.FleetGatewaySession, error) {
	at=at.UTC()
	cluster,err:=s.GetManagedCluster(ctx,clusterID);if err!=nil{return controlplane.FleetGatewaySession{},err}
	var out controlplane.FleetGatewaySession
	err=s.serializable(ctx,func(tx *sql.Tx)error{
		v,e:=scanFleetGatewaySession(tx.QueryRowContext(ctx,`SELECT `+fleetGatewaySessionColumns+` FROM fleet_gateway_sessions WHERE session_id=$1 FOR UPDATE`,strings.TrimSpace(sessionID)));if e!=nil{return mapDBError(e)}
		if v.ClusterID!=cluster.ID||v.CertificateID!=strings.TrimSpace(certificateID)||v.Epoch!=epoch{return controlplane.ErrNotFound}
		next,e:=controlplane.CloseFleetGatewaySession(v,at);if e!=nil{return e}
		if _,e=tx.ExecContext(ctx,`UPDATE fleet_gateway_sessions SET state='CLOSED',closed_at=$2 WHERE session_id=$1`,next.SessionID,at);e!=nil{return mapDBError(e)}
		if e=s.appendAuditTx(ctx,tx,"cluster-agent-gateway","fleet_gateway_session.closed","fleetGatewaySession",next.SessionID,next.Epoch,"",map[string]any{"projectId":cluster.ProjectID,"clusterId":cluster.ID,"epoch":next.Epoch});e!=nil{return e}
		if e=s.appendOutboxTx(ctx,tx,"fleetGatewaySession",next.SessionID,"fleet_gateway_session.closed",next);e!=nil{return e}
		out=next;return nil
	})
	return out,err
}
