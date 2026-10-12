// Package grpctransport serves the gRPC transport.
//
// The package is named grpctransport rather than grpc because the generated
// code and the gRPC runtime both live under that name, and a local package
// called `grpc` would shadow them at every import site in this file.
//
// Handlers here do what the REST handlers do: decode, call the service,
// encode. Both transports call the same internal/service methods, which is
// what keeps them from drifting — there is one implementation of "decrypt",
// and the tests assert the two transports produce the same answers.
package grpctransport

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pandav1 "github.com/jatimprovcsirt/panda-docker/gen/panda/v1"
	"github.com/jatimprovcsirt/panda-docker/internal/apierr"
	"github.com/jatimprovcsirt/panda-docker/internal/service"
)

// Server implements pandav1.PandaServiceServer.
type Server struct {
	pandav1.UnimplementedPandaServiceServer

	svc *service.Service
	log *slog.Logger
}

func New(svc *service.Service, log *slog.Logger) (*Server, error) {
	if svc == nil {
		return nil, errors.New("grpc: service is required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{svc: svc, log: log}, nil
}

// --- error mapping ---------------------------------------------------------

// toStatus maps a service error onto a gRPC status.
//
// The mapping is exhaustive over apierr's codes and its default is Internal,
// so a code added later without an entry here surfaces as a server fault to
// investigate rather than being quietly filed as a caller mistake.
func toStatus(err error) error {
	if err == nil {
		return nil
	}

	code := apierr.CodeOf(err)
	message := apierr.MessageOf(err)

	var grpcCode codes.Code
	switch code {
	case apierr.CodeMalformedEnvelope,
		apierr.CodeAuthFailed,
		apierr.CodeUnknownKID,
		apierr.CodeInvalidPlaintext:
		grpcCode = codes.InvalidArgument
	case apierr.CodeUnauthorized:
		grpcCode = codes.Unauthenticated
	case apierr.CodeForbidden, apierr.CodeShredDisabled:
		grpcCode = codes.PermissionDenied
	case apierr.CodeNotFound:
		grpcCode = codes.NotFound
	case apierr.CodePayloadTooLarge, apierr.CodeRateLimited:
		grpcCode = codes.ResourceExhausted
	case apierr.CodeKeyProviderUnavailable:
		grpcCode = codes.Unavailable
	default:
		grpcCode = codes.Internal
	}

	st := status.New(grpcCode, message)

	// Attach the service's own code as a detail, so a caller switching between
	// transports can key off the same string it would see in a REST response
	// rather than translating gRPC codes back into meanings.
	if detailed, err := st.WithDetails(&pandav1.ErrorDetail{Code: string(code)}); err == nil {
		return detailed.Err()
	}
	return st.Err()
}

// --- actor -----------------------------------------------------------------

// actorFromContext reads the caller identity out of gRPC metadata.
//
// mTLS identity is not available here — the transport security layer attaches
// it to the peer, not to metadata — so it is read at the connection level in
// Phase 3 and merged into the audit record there. What this can see is what
// the caller sent, which is recorded but not trusted.
func (s *Server) actorFromContext(ctx context.Context) service.Actor {
	actor := service.Actor{RequestID: "unset"}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return actor
	}

	if v := md.Get("x-request-id"); len(v) > 0 {
		actor.RequestID = v[0]
	}
	if v := md.Get("x-api-key-id"); len(v) > 0 {
		actor.APIKeyID = v[0]
	}
	return actor
}

// --- handlers --------------------------------------------------------------

func (s *Server) Encrypt(ctx context.Context, req *pandav1.EncryptRequest) (*pandav1.EncryptResponse, error) {
	result, err := s.svc.Encrypt(req.GetPlaintext(), req.GetKid())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pandav1.EncryptResponse{
		Envelope: result.Envelope,
		Kid:      result.KID,
		V:        int32(result.Version),
	}, nil
}

func (s *Server) Decrypt(ctx context.Context, req *pandav1.DecryptRequest) (*pandav1.DecryptResponse, error) {
	result, err := s.svc.Decrypt(s.actorFromContext(ctx), req.GetEnvelope())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pandav1.DecryptResponse{
		Value:  result.Value,
		Masked: true,
		Kid:    result.KID,
	}, nil
}

func (s *Server) DecryptRaw(ctx context.Context, req *pandav1.DecryptRawRequest) (*pandav1.DecryptRawResponse, error) {
	result, err := s.svc.DecryptRaw(s.actorFromContext(ctx), req.GetEnvelope())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pandav1.DecryptRawResponse{
		Value:   result.Plaintext,
		Masked:  false,
		Kid:     result.KID,
		AuditId: result.AuditID,
	}, nil
}

func (s *Server) Mask(ctx context.Context, req *pandav1.MaskRequest) (*pandav1.MaskResponse, error) {
	if req.GetValue() == "" {
		return nil, toStatus(apierr.New(apierr.CodeInvalidPlaintext, "value is empty"))
	}
	return &pandav1.MaskResponse{Value: s.svc.Mask(req.GetValue())}, nil
}

func (s *Server) BlindIndex(ctx context.Context, req *pandav1.BlindIndexRequest) (*pandav1.BlindIndexResponse, error) {
	if req.GetValue() == "" {
		return nil, toStatus(apierr.New(apierr.CodeInvalidPlaintext, "value is empty"))
	}

	index, err := s.svc.BlindIndex(req.GetValue(), req.GetKid())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pandav1.BlindIndexResponse{Index: index, Kid: req.GetKid()}, nil
}

func (s *Server) Version(ctx context.Context, req *pandav1.VersionRequest) (*pandav1.VersionResponse, error) {
	return &pandav1.VersionResponse{
		Service: s.svc.Describe(),
		Sdk:     service.SDKVersion(),
	}, nil
}
