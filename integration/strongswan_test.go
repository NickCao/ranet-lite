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
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const ikePort = "13000/udp"

func TestStrongSwanAndBIRDInterop(t *testing.T) {
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
		testcontainers.WithConfigModifier(func(config *container.Config) {
			// systemd writes service console output to /dev/console. Allocate a
			// terminal so the OCI runtime captures that console as live logs.
			config.Tty = true
		}),
		testcontainers.WithHostConfigModifier(func(hostConfig *container.HostConfig) {
			hostConfig.Privileged = true
			hostConfig.Tmpfs = map[string]string{
				"/run":      "rw",
				"/run/lock": "rw",
			}
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
			wait.ForLog(`Reached target .*ranet\.target`).AsRegexp().WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start strongSwan/BIRD gateway: %v", err)
	}
	testcontainers.CleanupContainer(t, container)
	stopLogs := streamGatewayLogs(t, ctx, container)
	defer stopLogs()
	defer logGateway(t, ctx, container)

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
		t.Fatalf("IKEv2 handshake: %v", err)
	}
	defer session.Mux().Close()

	if session.Child.LocalSPI == 0 || session.Child.RemoteSPI == 0 {
		t.Fatalf("strongSwan returned an invalid Child SA: %+v", session.Child)
	}

	sessionCtx, stopSession := context.WithCancel(ctx)
	defer stopSession()
	sessionResult := make(chan error, 1)
	go func() { sessionResult <- session.Run(sessionCtx) }()

	outbound, err := esp.NewOutbound(session.Child)
	if err != nil {
		t.Fatal(err)
	}
	inbound, err := esp.NewInbound(session.Child)
	if err != nil {
		t.Fatal(err)
	}
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := babel.New(babel.Config{
		LinkLocalAddr:  netip.MustParseAddr("fe80::2"),
		HelloInterval:  500 * time.Millisecond,
		UpdateInterval: time.Second,
	}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	peer := netstack.NewPeer("bird", outbound.Seal, session.Mux().SendESP)
	peerHandle := speaker.AddPeer(peer)
	defer peerHandle.Close()
	speaker.Originate(netip.MustParsePrefix("fd00:88::2/128"))
	go func() { _ = speaker.Run(sessionCtx) }()

	espResult := make(chan error, 1)
	go func() {
		for {
			packet, err := session.Mux().RecvESP()
			if err != nil {
				espResult <- err
				return
			}
			plain, _, err := inbound.Open(packet)
			if err != nil {
				espResult <- err
				return
			}
			speaker.Receive(peer, plain)
		}
	}()

	waitForBabelRoute(t, mesh.Routes, sessionResult, espResult, "fd00:99::/64")
}

func streamGatewayLogs(t *testing.T, ctx context.Context, container testcontainers.Container) func() {
	t.Helper()
	logCtx, cancel := context.WithCancel(ctx)
	apiClient, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		cancel()
		t.Fatalf("create container log client: %v", err)
	}
	logs, err := apiClient.ContainerLogs(logCtx, container.GetContainerID(), client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		cancel()
		_ = apiClient.Close()
		t.Fatalf("follow gateway logs: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(os.Stdout, logs); err != nil && logCtx.Err() == nil {
			t.Errorf("stream gateway logs: %v", err)
		}
	}()
	return func() {
		cancel()
		_ = logs.Close()
		<-done
		_ = apiClient.Close()
	}
}

func waitForBabelRoute(t *testing.T, routes *netstack.RouteTable, sessionResult, espResult <-chan error, prefix string) {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		for _, route := range routes.Debug() {
			if strings.HasPrefix(route, prefix+" ") {
				t.Logf("learned BIRD Babel route: %s", route)
				return
			}
		}
		select {
		case err := <-sessionResult:
			t.Fatalf("IKE session ended before Babel converged: %v", err)
		case err := <-espResult:
			t.Fatalf("ESP receive loop ended before Babel converged: %v", err)
		case <-ticker.C:
		case <-timer.C:
			t.Fatalf("timed out waiting for BIRD to advertise %s; routes: %v", prefix, routes.Debug())
		}
	}
}

func logGateway(t *testing.T, ctx context.Context, container *testcontainers.DockerContainer) {
	t.Helper()
	// Give charon's worker thread time to emit the final authentication result.
	time.Sleep(200 * time.Millisecond)
	logs, err := container.Logs(ctx)
	if err != nil {
		t.Logf("read gateway logs: %v", err)
		return
	}
	defer logs.Close()
	output, err := io.ReadAll(logs)
	if err != nil {
		t.Logf("read gateway logs: %v", err)
		return
	}
	t.Logf("strongSwan/BIRD logs:\n%s", output)
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
        if_id_in = 1
        if_id_out = 1
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
