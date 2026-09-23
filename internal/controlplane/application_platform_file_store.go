package controlplane

import "context"

func (f *FileStore) CreateWorkloadType(ctx context.Context,v WorkloadType,a string)(WorkloadType,error){return mutate(f,ctx,func()(WorkloadType,error){return f.MemoryStore.CreateWorkloadType(ctx,v,a)})}
func (f *FileStore) CreateCapabilityTrait(ctx context.Context,v CapabilityTrait,a string)(CapabilityTrait,error){return mutate(f,ctx,func()(CapabilityTrait,error){return f.MemoryStore.CreateCapabilityTrait(ctx,v,a)})}
func (f *FileStore) CreateManagedResourceType(ctx context.Context,v ManagedResourceType,a string)(ManagedResourceType,error){return mutate(f,ctx,func()(ManagedResourceType,error){return f.MemoryStore.CreateManagedResourceType(ctx,v,a)})}
func (f *FileStore) CreateWorkspaceProfile(ctx context.Context,v WorkspaceProfile,a string)(WorkspaceProfile,error){return mutate(f,ctx,func()(WorkspaceProfile,error){return f.MemoryStore.CreateWorkspaceProfile(ctx,v,a)})}
func (f *FileStore) CreateApplicationRelease(ctx context.Context,v ApplicationReleaseCreateRequest,a string)(ApplicationRelease,error){return mutate(f,ctx,func()(ApplicationRelease,error){return f.MemoryStore.CreateApplicationRelease(ctx,v,a)})}
func (f *FileStore) CreateEnvironmentBinding(ctx context.Context,v EnvironmentBindingCreateRequest,a string)(EnvironmentBinding,error){return mutate(f,ctx,func()(EnvironmentBinding,error){return f.MemoryStore.CreateEnvironmentBinding(ctx,v,a)})}
func (f *FileStore) PromoteEnvironmentBinding(ctx context.Context,id string,rev int64,v EnvironmentBindingPromotionRequest,a string)(EnvironmentBinding,error){return mutate(f,ctx,func()(EnvironmentBinding,error){return f.MemoryStore.PromoteEnvironmentBinding(ctx,id,rev,v,a)})}
