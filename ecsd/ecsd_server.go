package ecsd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/cipherowl-ai/openECS/proto"
	"github.com/cipherowl-ai/openECS/reload"
	"github.com/cipherowl-ai/openECS/store"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// gRPC server implementation
type EcsdServer struct {
	proto.UnimplementedECSdServer
	filter *store.BloomFilterStore
	reload *reload.ReloadManager
	logger *slog.Logger
}

func NewEcsdServer(filter *store.BloomFilterStore, reload *reload.ReloadManager, logger *slog.Logger) *EcsdServer {
	return &EcsdServer{
		filter: filter,
		reload: reload,
		logger: logger,
	}
}

// CheckAddress implements the gRPC CheckAddress method
func (s *EcsdServer) CheckAddress(ctx context.Context, req *proto.CheckAddressRequest) (*proto.CheckAddressResponse, error) {
	found, err := s.filter.CheckAddress(req.Address)
	if err != nil {
		return nil, err
	}

	return &proto.CheckAddressResponse{
		Address: req.Address,
		InSet:   found,
	}, nil
}

// BatchCheckAddresses implements the gRPC BatchCheckAddresses method
func (s *EcsdServer) BatchCheckAddresses(ctx context.Context, req *proto.BatchCheckRequest) (*proto.BatchCheckResponse, error) {
	if len(req.Addresses) > 100 {
		return nil, fmt.Errorf("too many addresses, maximum is 100")
	}

	found := make([]string, 0)
	notFound := make([]string, 0)

	for _, address := range req.Addresses {
		if ok, err := s.filter.CheckAddress(address); ok && err == nil {
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
func (s *EcsdServer) InspectFilter(ctx context.Context, req *proto.InspectRequest) (*proto.InspectResponse, error) {
	stats := s.filter.GetStats()

	return &proto.InspectResponse{
		K:                 int32(stats.K),
		M:                 int64(stats.M),
		N:                 int64(stats.N),
		EstimatedCapacity: int64(stats.EstimatedCapacity),
		FalsePositiveRate: stats.FalsePositiveRate,
		LastUpdate:        s.reload.LastLoadTime().Format(time.RFC3339),
	}, nil
}

func (s *EcsdServer) StartGRPCServer(grpcPort int) {
	// Start gRPC server in a goroutine
	go func() {
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
		if err != nil {
			s.logger.Error("Failed to listen for gRPC", "error", err)
			os.Exit(1)
		}

		srv := grpc.NewServer()
		proto.RegisterECSdServer(srv, s)
		// Enable reflection for debugging
		reflection.Register(srv)

		s.logger.Info("Starting gRPC server", "port", grpcPort)
		if err := srv.Serve(lis); err != nil {
			s.logger.Error("Failed to serve gRPC", "error", err)
			os.Exit(1)
		}
	}()
}
