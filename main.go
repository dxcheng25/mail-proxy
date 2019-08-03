package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"crypto/tls"
)

var (
	mailBackendAddr = flag.String("mail_backend_addr", "", "Address of the mail server backend that accepts forwarded requests.")
	smtpPrivatePort = flag.Int("smtp_private_port", 25, "Port for forwarding SMTP requests.")
	imapPrivatePort = flag.Int("imap_private_port", 143, "Port for forwarding IMAP requests.")
	sslCertKey      = flag.String("ssl_cert_key", "", "Path to the certificate key file.")
	sslCert         = flag.String("ssl_cert", "", "Path to the certificate file.")
	verbose         = flag.Bool("verbose", false, "If set to true, print out all traffic payloads for debugging.")
)

const (
	SmtpSslPublicPort = 587
	SmtpPublicPort    = 25
	ImapPublicPort    = 993
)

func acceptConnections(l net.Listener, handler func(net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			log.Println(err)
			return
		}
		log.Printf("Client: %s connected to %s.", c.RemoteAddr(), c.LocalAddr())
		go handler(c)
	}
}

func handleImapConnection(c net.Conn) {
	forwardTraffic(c, fmt.Sprintf("%s:%d", *mailBackendAddr, *imapPrivatePort))
}

func handleSmtpConnection(c net.Conn) {
	forwardTraffic(c, fmt.Sprintf("%s:%d", *mailBackendAddr, *smtpPrivatePort))
}

type SmtpConn struct {
	conn net.Conn
}

func (sc *SmtpConn) Read(p []byte) (int, error) {
	buf := make([]byte, 1024)
	n, err := sc.conn.Read(buf)
	if err != nil || n == 0 {
		return n, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(buf))
	scanner.Split(bufio.ScanLines)
	strippedbuf := new(bytes.Buffer)
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("Read line: %s", line)
		if line == "250-STARTTLS" {
			log.Printf("Received STARTTLS, upgrading connection to TLS.")
			w := bufio.NewWriter(sc.conn)
			w.WriteString("STARTTLS\r\n")
			w.WriteString("220 2.0.0 Ready to start TLS\r\n")
			sc.conn = tls.Server(sc.conn, getTLSConfig())
		} else {
			strippedbuf.WriteString(line + "\r\n")
		}
	}
	if strippedbuf.Len() > 0 && *verbose {
		log.Printf("Read traffic from %s, payload: %s", sc.conn.RemoteAddr(), strippedbuf.String())
	}
	copy(p, strippedbuf.Bytes())
	return len(p), nil
}

func (sc *SmtpConn) Write(p []byte) (int, error) {
	n, err := sc.conn.Write(p)
	if n > 0 && *verbose {
		log.Printf("Wrote traffic to %s, payload: %s", sc.conn.RemoteAddr(), p)
	}
	return n, err
}

func forwardTraffic(src net.Conn, dstaddr string) {
	defer src.Close()
	dst, err := net.Dial("tcp", dstaddr)
	if err != nil {
		log.Printf("Unable to connect to mail backend: %s, err: %v", *mailBackendAddr, err)
		return
	}
	defer dst.Close()

	log.Printf("Forwarding traffic from %s to %s.", src.RemoteAddr(), dst.RemoteAddr())
	psrc := &SmtpConn{conn: src}
	pdst := &SmtpConn{conn: dst}
	errc := make(chan error, 1)
	go copyPayload(errc, psrc, pdst)
	go copyPayload(errc, pdst, psrc)

	// Blocks until the first error / EOF.
	<-errc
}

func copyPayload(errc chan<- error, src, dst *SmtpConn) {
	_, err := io.Copy(dst, src)
	if err != nil {
		log.Printf("io.Copy from %s to %s returned with error: %v", src.conn.RemoteAddr(), dst.conn.RemoteAddr(), err)
	}
	errc <- err
}

func getTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(*sslCert, *sslCertKey)
	if err != nil {
		log.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func main() {
	flag.Parse()

	tlsconf := getTLSConfig()
	smtp, err := net.Listen("tcp4", fmt.Sprintf(":%d", SmtpPublicPort))
	if err != nil {
		log.Fatal(err)
	}
	defer smtp.Close()

	smtpssl, err := tls.Listen("tcp4", fmt.Sprintf(":%d", SmtpSslPublicPort), tlsconf)
	if err != nil {
		log.Fatal(err)
	}
	defer smtp.Close()

	imap, err := tls.Listen("tcp4", fmt.Sprintf(":%d", ImapPublicPort), tlsconf)
	if err != nil {
		log.Fatal(err)
	}
	defer imap.Close()

	donec := make(chan bool, 1)
	go acceptConnections(smtp, handleSmtpConnection)
	go acceptConnections(smtpssl, handleSmtpConnection)
	go acceptConnections(imap, handleImapConnection)
	<-donec
}
