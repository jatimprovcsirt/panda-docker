package grpctransport

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"github.com/jatimprovcsirt/panda-go/crypto"

	pandav1 "github.com/jatimprovcsirt/panda-docker/gen/panda/v1"
	"github.com/jatimprovcsirt/panda-docker/internal/apierr"
	"github.com/jatimprovcsirt/panda-docker/internal/service"
)

const testKID = "testkey"

func newTestClient(t *testing.T) (pandav1.PandaServiceClient, *service.Service) {
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

	handler, err := New(svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer(grpc.ChainUnaryInterceptor(RecoverInterceptor(slog.New(slog.NewTextHandler(io.Discard, nil)))))
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

	return pandav1.NewPandaServiceClient(conn), svc
}

// --- the round trip -------------------------------------------------------

func TestEncryptDecryptRoundTrip(t *testing.T) {
	client, _ := newTestClient(t)
	ctx := context.Background()

	const nik = "3201012501990001"

	enc, err := client.Encrypt(ctx, &pandav1.EncryptRequest{Plaintext: nik, Kid: testKID})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if enc.GetV() != 1 {
		t.Errorf("version = %d, want 1", enc.GetV())
	}
	if enc.GetEnvelope() == "" {
		t.Fatal("no envelope returned")
	}

	dec, err := client.Decrypt(ctx, &pandav1.DecryptRequest{Envelope: enc.GetEnvelope()})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if dec.GetValue() != "32************01" {
		t.Errorf("masked = %q, want 32************01", dec.GetValue())
	}
	if !dec.GetMasked() {
		t.Error("masked flag is false on the masked read path")
	}
	if dec.GetKid() != testKID {
		t.Errorf("kid = %q, want %q", dec.GetKid(), testKID)
	}

	raw, err := client.DecryptRaw(ctx, &pandav1.DecryptRawRequest{Envelope: enc.GetEnvelope()})
	if err != nil {
		t.Fatalf("DecryptRaw: %v", err)
	}
	if raw.GetValue() != nik {
		t.Errorf("raw = %q, want the plaintext", raw.GetValue())
	}
	if raw.GetMasked() {
		t.Error("masked flag is true on the unmask path")
	}
}

// --- error mapping --------------------------------------------------------

func TestErrorsCarryTheServiceCode(t *testing.T) {
	// gRPC status codes are coarser than this service's contract. The detail
	// is what lets a client key off the same string it would see in a REST
	// error body.
	client, _ := newTestClient(t)
	ctx := context.Background()

	_, err := client.Decrypt(ctx, &pandav1.DecryptRequest{Envelope: "not an envelope"})
	if err == nil {
		t.Fatal("a malformed envelope was accepted")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("not a gRPC status: %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", st.Code())
	}

	var found string
	for _, d := range st.Details() {
		if detail, ok := d.(*pandav1.ErrorDetail); ok {
			found = detail.GetCode()
		}
	}
	if found != string(apierr.CodeMalformedEnvelope) {
		t.Errorf("error detail = %q, want %q", found, apierr.CodeMalformedEnvelope)
	}
}

func TestUnknownKIDMapsToInvalidArgument(t *testing.T) {
	client, _ := newTestClient(t)
	ctx := context.Background()

	enc, err := client.Encrypt(ctx, &pandav1.EncryptRequest{Plaintext: "3201012501990001", Kid: testKID})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	env, _ := crypto.ParseEnvelope(enc.GetEnvelope())
	env.Kid = "no-such-key"
	orphaned, _ := env.ToJSON()

	_, err = client.Decrypt(ctx, &pandav1.DecryptRequest{Envelope: orphaned})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestTamperedEnvelopeMapsToInvalidArgument(t *testing.T) {
	client, _ := newTestClient(t)
	ctx := context.Background()

	enc, _ := client.Encrypt(ctx, &pandav1.EncryptRequest{Plaintext: "3201012501990001", Kid: testKID})

	env, _ := crypto.ParseEnvelope(enc.GetEnvelope())
	raw, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
	raw[0] ^= 0xFF
	env.Ciphertext = base64.StdEncoding.EncodeToString(raw)
	tampered, _ := env.ToJSON()

	_, err := client.Decrypt(ctx, &pandav1.DecryptRequest{Envelope: tampered})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestEmptyInputIsRejected(t *testing.T) {
	client, _ := newTestClient(t)
	ctx := context.Background()

	if _, err := client.Encrypt(ctx, &pandav1.EncryptRequest{Plaintext: ""}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty plaintext: code = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := client.Mask(ctx, &pandav1.MaskRequest{Value: ""}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty mask value: code = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := client.BlindIndex(ctx, &pandav1.BlindIndexRequest{Value: ""}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty index value: code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestErrorMessagesDoNotLeakInternals(t *testing.T) {
	client, _ := newTestClient(t)
	ctx := context.Background()

	enc, _ := client.Encrypt(ctx, &pandav1.EncryptRequest{Plaintext: "3201012501990001", Kid: testKID})
	env, _ := crypto.ParseEnvelope(enc.GetEnvelope())
	env.Kid = "../../etc/passwd"
	orphaned, _ := env.ToJSON()

	_, err := client.Decrypt(ctx, &pandav1.DecryptRequest{Envelope: orphaned})
	if strings.Contains(status.Convert(err).Message(), "passwd") {
		t.Fatalf("the message leaks the kid: %q", status.Convert(err).Message())
	}
}

// --- the envelope stays a string ------------------------------------------

func TestEnvelopeSurvivesTheProtoRoundTrip(t *testing.T) {
	// The envelope travels as a JSON string precisely so panda-spec stays the
	// single definition of its shape. If it were decomposed into proto fields,
	// an envelope v2 with a new field would be silently truncated here.
	client, _ := newTestClient(t)
	ctx := context.Background()

	enc, err := client.Encrypt(ctx, &pandav1.EncryptRequest{Plaintext: "3201012501990001", Kid: testKID})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	parsed, err := crypto.ParseEnvelope(enc.GetEnvelope())
	if err != nil {
		t.Fatalf("the returned envelope does not parse as an envelope: %v", err)
	}
	if parsed.Kid != testKID || parsed.V != 1 {
		t.Errorf("envelope fields lost in transit: %+v", parsed)
	}

	// And it survives being serialised as a proto message, which is what a
	// client on the other end does.
	wire, err := proto.Marshal(enc)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	back := &pandav1.EncryptResponse{}
	if err := proto.Unmarshal(wire, back); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if back.GetEnvelope() != enc.GetEnvelope() {
		t.Error("the envelope changed across a proto round trip")
	}
}

// --- other operations -----------------------------------------------------

func TestMaskAndBlindIndex(t *testing.T) {
	client, _ := newTestClient(t)
	ctx := context.Background()

	masked, err := client.Mask(ctx, &pandav1.MaskRequest{Value: "3201012501990001"})
	if err != nil {
		t.Fatalf("Mask: %v", err)
	}
	if masked.GetValue() != "32************01" {
		t.Errorf("masked = %q", masked.GetValue())
	}

	a, err := client.BlindIndex(ctx, &pandav1.BlindIndexRequest{Value: "3201012501990001", Kid: testKID})
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	b, _ := client.BlindIndex(ctx, &pandav1.BlindIndexRequest{Value: "3201012501990001", Kid: testKID})
	if a.GetIndex() == "" || a.GetIndex() != b.GetIndex() {
		t.Errorf("index is not deterministic: %q vs %q", a.GetIndex(), b.GetIndex())
	}
}

func TestVersionReportsTheSDK(t *testing.T) {
	client, _ := newTestClient(t)

	v, err := client.Version(context.Background(), &pandav1.VersionRequest{})
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v.GetService() == "" {
		t.Error("no service description")
	}
	if v.GetSdk() == "" {
		t.Error("no SDK version")
	}
}

func TestNewRequiresAService(t *testing.T) {
	if _, err := New(nil, nil); err == nil {
		t.Fatal("a server was constructed with no service")
	}
}
