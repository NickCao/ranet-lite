//go:build integration

package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const ikePort = "13000/udp"

func TestStrongSwanHandshake(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixtureDir := writeStrongSwanCredentials(t, publicKey, privateKey)

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate integration test fixtures")
	}
	container, err := testcontainers.Run(ctx, "",
		testcontainers.WithDockerfile(testcontainers.FromDockerfile{
			Context:    filepath.Dir(sourceFile),
			Dockerfile: "Dockerfile",
		}),
		testcontainers.WithExposedPorts(ikePort),
		testcontainers.WithHostConfigModifier(func(hostConfig *container.HostConfig) {
			hostConfig.CapAdd = append(hostConfig.CapAdd, "NET_ADMIN", "NET_RAW")
		}),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{
				HostFilePath:      filepath.Join(fixtureDir, "swanctl.conf"),
				ContainerFilePath: "/etc/swanctl/swanctl.conf",
				FileMode:          0o600,
			},
			testcontainers.ContainerFile{
				HostFilePath:      filepath.Join(fixtureDir, "org-key.pem"),
				ContainerFilePath: "/etc/swanctl/private/org-key.pem",
				FileMode:          0o600,
			},
			testcontainers.ContainerFile{
				HostFilePath:      filepath.Join(fixtureDir, "org-pub.pem"),
				ContainerFilePath: "/etc/swanctl/pubkey/org-pub.pem",
				FileMode:          0o644,
			},
		),
		testcontainers.WithWaitStrategy(
			wait.ForLog("strongSwan ready").WithStartupTimeout(2*time.Minute),
		),
	)
	if err != nil {
		t.Fatalf("start strongSwan: %v", err)
	}
	testcontainers.CleanupContainer(t, container)

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, ikePort)
	if err != nil {
		t.Fatal(err)
	}
	remote := net.ParseIP(host)
	if remote == nil {
		ips, lookupErr := net.LookupIP(host)
		if lookupErr != nil || len(ips) == 0 {
			t.Fatalf("resolve container host %q: %v", host, lookupErr)
		}
		remote = ips[0]
	}

	session, err := ike.Initiate(ike.PeerConfig{
		Organization:     "testorg",
		LocalCommonName:  "client",
		LocalSerial:      "2",
		LocalPrivateKey:  privateKey,
		RemoteCommonName: "server",
		RemoteSerial:     "1",
		RemotePublicKey:  publicKey,
		LocalAddr:        net.ParseIP("127.0.0.1"),
		RemoteAddr:       remote,
		RemotePort:       int(port.Num()),
	})
	if err != nil {
		// Give charon's worker thread time to emit the authentication reason
		// before collecting logs and terminating the container.
		time.Sleep(200 * time.Millisecond)
		logs, logsErr := container.Logs(ctx)
		if logsErr == nil {
			defer logs.Close()
			output, _ := io.ReadAll(logs)
			t.Logf("strongSwan logs:\n%s", output)
		}
		t.Fatalf("IKEv2 handshake: %v", err)
	}
	defer session.Mux().Close()

	if session.Child.LocalSPI == 0 || session.Child.RemoteSPI == 0 {
		t.Fatalf("strongSwan returned an invalid Child SA: %+v", session.Child)
	}
}

func writeStrongSwanCredentials(t *testing.T, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) string {
	t.Helper()
	dir := t.TempDir()

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "org-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	writeFile(t, filepath.Join(dir, "org-pub.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)

	config := `connections {
    ranet {
        version = 2
        local_addrs = 0.0.0.0/0
        remote_addrs = 0.0.0.0/0
        local_port = 13000
        proposals = aes256gcm16-prfsha384-curve25519, aes128gcm16-prfsha256-curve25519, chacha20poly1305-prfsha256-curve25519
        encap = yes
        mobike = no

        local {
            auth = pubkey
            pubkeys = org-pub.pem
            id = "O=testorg, CN=server, serialNumber=1"
        }
        remote {
            auth = pubkey
            pubkeys = org-pub.pem
            id = "O=testorg, CN=client, serialNumber=2"
        }
        children {
            mesh {
                mode = tunnel
                local_ts = 0.0.0.0/0, ::/0
                remote_ts = 0.0.0.0/0, ::/0
                esp_proposals = aes256gcm16-noesn, aes128gcm16-noesn, chacha20poly1305-noesn
                start_action = none
            }
        }
    }
}

secrets {
    private-org {
        file = /etc/swanctl/private/org-key.pem
    }
}
`
	writeFile(t, filepath.Join(dir, "swanctl.conf"), []byte(config), 0o600)
	return dir
}

func writeFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
}
