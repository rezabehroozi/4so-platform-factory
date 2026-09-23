package controlplane

import (
	"context"
	"time"
)

func (f *FileStore) AdmitFleetGatewaySession(ctx context.Context, req FleetGatewaySessionRequest, at time.Time, actor string) (FleetGatewaySessionAdmission, error) {
	return mutate(f, ctx, func() (FleetGatewaySessionAdmission, error) { return f.MemoryStore.AdmitFleetGatewaySession(ctx, req, at, actor) })
}
func (f *FileStore) HeartbeatFleetGatewaySession(ctx context.Context, clusterID, sessionID string, epoch int64, certificateID string, at time.Time) (FleetGatewaySession, error) {
	return mutate(f, ctx, func() (FleetGatewaySession, error) { return f.MemoryStore.HeartbeatFleetGatewaySession(ctx, clusterID, sessionID, epoch, certificateID, at) })
}
func (f *FileStore) DrainFleetGatewaySession(ctx context.Context, clusterID string, expectedEpoch int64, actor string, at time.Time) (FleetGatewaySession, error) {
	return mutate(f, ctx, func() (FleetGatewaySession, error) { return f.MemoryStore.DrainFleetGatewaySession(ctx, clusterID, expectedEpoch, actor, at) })
}
func (f *FileStore) CloseFleetGatewaySession(ctx context.Context, clusterID, sessionID string, epoch int64, certificateID string, at time.Time) (FleetGatewaySession, error) {
	return mutate(f, ctx, func() (FleetGatewaySession, error) { return f.MemoryStore.CloseFleetGatewaySession(ctx, clusterID, sessionID, epoch, certificateID, at) })
}
