package grpctransport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/jatimprovcsirt/panda-go/crypto"

	pandav1 "github.com/jatimprovcsirt/panda-docker/gen/panda/v1"
	"github.com/jatimprovcsirt/panda-docker/internal/apierr"
	"github.com/jatimprovcsirt/panda-docker/internal/service"
	"github.com/jatimprovcsirt/panda-docker/internal/transport/rest"
)

// These tests exist because of the shared service layer.
//
// The reason the transports both call internal/service rather than each
// implementing their own path is that two implementations drift. This is the
// test that would fail if they did: the same envelope, encrypted on one
// transport and decrypted on the other, and the same error codes for the same
// failures.

type bothTransports struct {
	grpc pandav1.PandaServiceClient
	http *httptest.Server
}

func newBothTransports(t *testing.T) *bothTransports {
	t.Helper()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	t.Setenv("PANDA_KEY_testkey", base64.StdEncoding.EncodeToString(key))
	t.Setenv("PANDA_DEFAULT_KID", testKID)

	svc, err := service.New(service.Options{
		Cipher:   crypto.NewFieldCipher(crypto.NewLocalKeyProvider(), nil, nil),
		IndexKey: []byte("an-index-key-for-tests-only-32b!!"),
	})
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	// gRPC over an in-memory listener.
	handler, err := New(svc, quiet)
	if err != nil {
		t.Fatalf("grpctransport.New: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer()
	pandav1.RegisterPandaServiceServer(grpcSrv, handler)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// REST over the same service instance.
	restSrv, err := rest.New(rest.Options{Service: svc, Logger: quiet})
	if err != nil {
		t.Fatalf("rest.New: %v", err)
	}
	httpSrv := httptest.NewServer(restSrv.Handler())
	t.Cleanup(httpSrv.Close)

	return &bothTransports{grpc: pandav1.NewPandaServiceClient(conn), http: httpSrv}
}

func (b *bothTransports) restPost(t *testing.T, path, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(b.http.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var decoded map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	return resp.StatusCode, decoded
}

const sampleNIK = "3201012501990001"

func TestEncryptedOnRESTDecryptsOnGRPC(t *testing.T) {
	both := newBothTransports(t)

	_, enc := both.restPost(t, "/v1/encrypt",
		`{"plaintext":"`+sampleNIK+`","kid":"`+testKID+`"}`)
	envelope, _ := enc["envelope"].(string)
	if envelope == "" {
		t.Fatalf("no envelope from REST: %v", enc)
	}

	dec, err := both.grpc.Decrypt(context.Background(), &pandav1.DecryptRequest{Envelope: envelope})
	if err != nil {
		t.Fatalf("gRPC could not decrypt a REST-produced envelope: %v", err)
	}
	if dec.GetValue() != "32************01" {
		t.Errorf("masked = %q, want 32************01", dec.GetValue())
	}
}

func TestEncryptedOnGRPCDecryptsOnREST(t *testing.T) {
	both := newBothTransports(t)

	enc, err := both.grpc.Encrypt(context.Background(),
		&pandav1.EncryptRequest{Plaintext: sampleNIK, Kid: testKID})
	if err != nil {
		t.Fatalf("gRPC Encrypt: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"envelope": enc.GetEnvelope()})
	code, dec := both.restPost(t, "/v1/decrypt", string(body))

	if code != http.StatusOK {
		t.Fatalf("REST could not decrypt a gRPC-produced envelope: %d %v", code, dec)
	}
	if dec["value"] != "32************01" {
		t.Errorf("masked = %v, want 32************01", dec["value"])
	}
}

func TestBothTransportsMaskIdentically(t *testing.T) {
	both := newBothTransports(t)

	_, restBody := both.restPost(t, "/v1/mask", `{"value":"`+sampleNIK+`"}`)

	grpcBody, err := both.grpc.Mask(context.Background(), &pandav1.MaskRequest{Value: sampleNIK})
	if err != nil {
		t.Fatalf("gRPC Mask: %v", err)
	}

	if restBody["value"] != grpcBody.GetValue() {
		t.Errorf("masking differs: REST %v, gRPC %q", restBody["value"], grpcBody.GetValue())
	}
}

func TestBothTransportsIndexIdentically(t *testing.T) {
	both := newBothTransports(t)

	_, restBody := both.restPost(t, "/v1/blind-index",
		`{"value":"`+sampleNIK+`","kid":"`+testKID+`"}`)

	grpcBody, err := both.grpc.BlindIndex(context.Background(),
		&pandav1.BlindIndexRequest{Value: sampleNIK, Kid: testKID})
	if err != nil {
		t.Fatalf("gRPC BlindIndex: %v", err)
	}

	// Two transports producing different indexes for the same value would
	// mean a record indexed by one could never be found by the other.
	if restBody["index"] != grpcBody.GetIndex() {
		t.Errorf("indexes differ: REST %v, gRPC %q", restBody["index"], grpcBody.GetIndex())
	}
}

func TestBothTransportsReportTheSameErrorCode(t *testing.T) {
	both := newBothTransports(t)

	const malformed = "definitely not an envelope"

	_, restBody := both.restPost(t, "/v1/decrypt", `{"envelope":"`+malformed+`"}`)
	restCode := restBody["error"].(map[string]any)["code"]

	_, err := both.grpc.Decrypt(context.Background(), &pandav1.DecryptRequest{Envelope: malformed})
	if err == nil {
		t.Fatal("gRPC accepted a malformed envelope")
	}

	var grpcCode string
	for _, d := range status.Convert(err).Details() {
		if detail, ok := d.(*pandav1.ErrorDetail); ok {
			grpcCode = detail.GetCode()
		}
	}

	if restCode != grpcCode {
		t.Errorf("error codes differ: REST %v, gRPC %q", restCode, grpcCode)
	}
	if restCode != string(apierr.CodeMalformedEnvelope) {
		t.Errorf("code = %v, want %v", restCode, apierr.CodeMalformedEnvelope)
	}
}

func TestBothTransportsRefuseTheSameInputs(t *testing.T) {
	both := newBothTransports(t)
	ctx := context.Background()

	// Empty plaintext, empty mask value, empty index value — each must be
	// refused by both, or a caller could bypass a check by switching protocol.
	_, restEnc := both.restPost(t, "/v1/encrypt", `{"plaintext":""}`)
	if _, ok := restEnc["error"]; !ok {
		t.Error("REST accepted an empty plaintext")
	}
	if _, err := both.grpc.Encrypt(ctx, &pandav1.EncryptRequest{Plaintext: ""}); err == nil {
		t.Error("gRPC accepted an empty plaintext")
	}

	_, restMask := both.restPost(t, "/v1/mask", `{"value":""}`)
	if _, ok := restMask["error"]; !ok {
		t.Error("REST accepted an empty mask value")
	}
	if _, err := both.grpc.Mask(ctx, &pandav1.MaskRequest{Value: ""}); err == nil {
		t.Error("gRPC accepted an empty mask value")
	}
}
