package socks5

import (
	"bufio"
	go_proxy "golang.org/x/net/proxy"
	"io"
	"net"
	"testing"
	"time"
)

func testEchoService(r io.ReadCloser, w io.WriteCloser) error {
	defer func() {
		_ = r.Close()
		_ = w.Close()
	}()

	scanner := bufio.NewReader(r)

	var line []byte
	for true {
		l, prefix, err := scanner.ReadLine()
		if err == io.EOF {
			if len(line) == 0 {
				return nil
			}
		} else if err != nil {
			return err
		} else if prefix {
			line = append(line, l...)
			continue
		} else {
			line = append(line, l...)
		}

		response := append(line, '\r', '\n')
		if _, err := w.Write(response); err != nil {
			return err
		}
		if string(line) == "QUIT" {
			break
		}

		line = make([]byte, 0)

		if err == io.EOF {
			return nil
		}
	}

	return nil
}

func testSetupEchoService(t *testing.T) (func(), error) {
	shutdown := make(chan bool, 1)
	l, err := net.Listen("tcp", "127.0.0.1:54000")
	if err != nil {
		t.Fatalf("Could not start proxy: %v", err)
	}

	go func() {
		for {
			var conn net.Conn

			select {
			case <-shutdown:
				return
			default:
				conn, err = l.Accept()
			}

			select {
			case <-shutdown:
				return
			default:
				if err != nil {
					panic(err)
				}
			}

			go func(c net.Conn) {
				err := testEchoService(c, c)
				if err != nil {
					panic(err)
				}
			}(conn)
		}
	}()

	return func() {
		shutdown <- true
		_ = l.Close()
	}, nil
}

func testHelloEcho(t *testing.T, conn io.ReadWriteCloser) {
	var err error

	scanner := bufio.NewScanner(conn)

	_, err = conn.Write([]byte("HELLO\r\n"))
	if err != nil {
		t.Fatalf("Could not start echo service: %v", err)
	}
	if !scanner.Scan() {
		t.Fatalf("Could not get first line from echo service")
	}
	if "HELLO" != scanner.Text() {
		t.Fatalf("Expected HELLO bug got something else")
	}
	_, err = conn.Write([]byte("QUIT\r\n"))
	if err != nil {
		t.Fatalf("Could not start echo service: %v", err)
	}
	if !scanner.Scan() {
		t.Fatalf("Could not get first line from echo service")
	}
	if "QUIT" != scanner.Text() {
		t.Fatalf("Expected QUIT bug got something else")
	}
	if scanner.Scan() {
		t.Fatalf("Expected FALSE but got TRUE")
	}
}

type testDialer struct {
	conn net.Conn
}

func (t *testDialer) Dial(network, addr string) (c net.Conn, err error) {
	return t.conn, nil
}

type testSimulatedConnection struct {
	reader     io.ReadCloser
	writer     io.WriteCloser
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (t *testSimulatedConnection) Read(b []byte) (n int, err error) {
	return t.reader.Read(b)
}

func (t *testSimulatedConnection) Write(b []byte) (n int, err error) {
	return t.writer.Write(b)
}

func (t *testSimulatedConnection) Close() error {
	_ = t.reader.Close()
	_ = t.writer.Close()
	return nil
}

func (t *testSimulatedConnection) LocalAddr() net.Addr {
	return t.localAddr
}

func (t *testSimulatedConnection) RemoteAddr() net.Addr {
	return t.remoteAddr
}

func (t *testSimulatedConnection) SetDeadline(time time.Time) error {
	// ignore
	return nil
}

func (t *testSimulatedConnection) SetReadDeadline(time time.Time) error {
	// ignore
	return nil
}

func (t *testSimulatedConnection) SetWriteDeadline(time time.Time) error {
	// ignore
	return nil
}

// TestSOCKS5_Close will test closing the connection from the server side
func TestSOCKS5_Close(t *testing.T) {

	echoServiceClose, err := testSetupEchoService(t)
	if err != nil {
		t.Fatalf("Could not start echo service: %v", err)
	}
	defer echoServiceClose()

	conf := &Config{}
	server, err := New(conf)

	if err != nil {
		t.Fatalf("Could not start proxy: %v", err)
	}

	addr1, err := net.ResolveTCPAddr("tcp", "localhost:54000")
	if err != nil {
		t.Fatalf("Could not resolve network address: %v", err)
	}

	addr2, err := net.ResolveTCPAddr("tcp", "localhost:54001")
	if err != nil {
		t.Fatalf("Could not resolve network address: %v", err)
	}

	clientReader, serverWriter := io.Pipe()
	serverReader, clientWriter := io.Pipe()

	clientConnection := &testSimulatedConnection{clientReader, clientWriter, addr1, addr2}
	serverConnection := &testSimulatedConnection{serverReader, serverWriter, addr2, addr1}

	done := make(chan error, 0)
	go func() {
		done <- server.ServeConn(serverConnection)
	}()

	dialer, err := go_proxy.SOCKS5("tcp", "this-is-ignored:54001", nil, &testDialer{
		conn: clientConnection,
	})
	if err != nil {
		t.Fatalf("Could not start proxy client: %v", err)
	}

	conn, err := dialer.Dial("tcp", "127.0.0.1:54000") // The address of the echo service
	if err != nil {
		t.Fatalf("Could not connect to echo service: %v", err)
	}

	testHelloEcho(t, conn)

}
