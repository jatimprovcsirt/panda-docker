package grpctransport

import (
	"context"
	"log/slog"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoverInterceptor turns a panic into an Internal status.
//
// Without it a panic in a handler takes down the whole process — every
// in-flight RPC on every connection, not just the one that panicked. The stack
// goes to the log and never to the caller: a stack trace is a map of the
// service's internals, and a client cannot act on one anyway.
func RecoverInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("panic in gRPC handler",
					"method", info.FullMethod,
					"panic", rec,
					"stack", string(debug.Stack()),
				)
				err = status.Error(codes.Internal, "an unexpected error occurred")
			}
		}()

		return handler(ctx, req)
	}
}
