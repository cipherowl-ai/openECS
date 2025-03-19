package main

import (
	"context"
	"fmt"
	"github.com/cipherowl-ai/addressdb/proto"
	"time"
)

// gRPC server implementation
type ecsdServer struct {
	proto.UnimplementedECSdServer
}

// CheckAddress implements the gRPC CheckAddress method
func (s *ecsdServer) CheckAddress(ctx context.Context, req *proto.CheckAddressRequest) (*proto.CheckAddressResponse, error) {
	found, err := filter.CheckAddress(req.Address)
	if err != nil {
		return nil, err
	}

	return &proto.CheckAddressResponse{
		Address: req.Address,
		InSet:   found,
	}, nil
}

// BatchCheckAddresses implements the gRPC BatchCheckAddresses method
func (s *ecsdServer) BatchCheckAddresses(ctx context.Context, req *proto.BatchCheckRequest) (*proto.BatchCheckResponse, error) {
	if len(req.Addresses) > 100 {
		return nil, fmt.Errorf("too many addresses, maximum is 100")
	}

	found := make([]string, 0)
	notFound := make([]string, 0)

	for _, address := range req.Addresses {
		if ok, err := filter.CheckAddress(address); ok && err == nil {
			found = append(found, address)
		} else {
			notFound = append(notFound, address)
		}
	}

	return &proto.BatchCheckResponse{
		Found:         found,
		NotFound:      notFound,
		FoundCount:    int32(len(found)),
		NotFoundCount: int32(len(notFound)),
	}, nil
}

// InspectFilter implements the gRPC InspectFilter method
func (s *ecsdServer) InspectFilter(ctx context.Context, req *proto.InspectRequest) (*proto.InspectResponse, error) {
	stats := filter.GetStats()

	return &proto.InspectResponse{
		K:                 int32(stats.K),
		M:                 int64(stats.M),
		N:                 int64(stats.N),
		EstimatedCapacity: int64(stats.EstimatedCapacity),
		FalsePositiveRate: stats.FalsePositiveRate,
		LastUpdate:        lastFilterLoadTime.Format(time.RFC3339),
	}, nil
}
