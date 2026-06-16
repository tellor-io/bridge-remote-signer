package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"

	bridgetls "github.com/tellor-io/bridge-remote-signer/api/tls"
)

// testPKI is an in-memory certificate authority for mTLS tests. It mints a
// server certificate (localhost / 127.0.0.1 SANs) and client certificates with
// arbitrary CommonNames, all chained to one CA and written to temp files so the
// production bridgetls credential builders load them unchanged. This lets the
// tests exercise the real RequireAndVerifyClientCert + per-cert CN auth path
// rather than a stub.
type testPKI struct {
	t      *testing.T
	dir    string
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPath string
	serial int64
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	caPath := filepath.Join(dir, "ca.crt")
	writePEM(t, caPath, "CERTIFICATE", der)
	return &testPKI{t: t, dir: dir, caCert: caCert, caKey: caKey, caPath: caPath, serial: 1}
}

// leaf mints a CA-signed leaf certificate. server=true gives it the
// localhost/127.0.0.1 SANs + serverAuth EKU; server=false gives it clientAuth.
func (p *testPKI) leaf(name, cn string, server bool) (certPath, keyPath string) {
	p.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatalf("gen leaf key: %v", err)
	}
	p.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		p.t.Fatalf("create leaf cert: %v", err)
	}
	certPath = filepath.Join(p.dir, name+".crt")
	keyPath = filepath.Join(p.dir, name+".key")
	writePEM(p.t, certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		p.t.Fatalf("marshal leaf key: %v", err)
	}
	writePEM(p.t, keyPath, "PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func (p *testPKI) serverCreds() credentials.TransportCredentials {
	p.t.Helper()
	certPath, keyPath := p.leaf("server", "test-signer", true)
	creds, err := bridgetls.NewServerCredentials(p.caPath, certPath, keyPath)
	if err != nil {
		p.t.Fatalf("server creds: %v", err)
	}
	return creds
}

func (p *testPKI) clientCreds(cn string) credentials.TransportCredentials {
	p.t.Helper()
	certPath, keyPath := p.leaf("client-"+cn, cn, false)
	creds, err := bridgetls.NewClientCredentials(p.caPath, certPath, keyPath, "localhost")
	if err != nil {
		p.t.Fatalf("client creds: %v", err)
	}
	return creds
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
