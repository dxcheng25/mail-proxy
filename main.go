package main

import (
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

type PrintingConn struct {
	conn net.Conn
}

func (pc *PrintingConn) Read(p []byte) (int, error) {
	n, err := pc.conn.Read(p)
	if *verbose {
		log.Printf("Read traffic payload: %v", p)
	}
	return n, err
}

func (pc *PrintingConn) Write(p []byte) (int, error) {
	n, err := pc.conn.Write(p)
	if *verbose {
		log.Printf("Wrote traffic payload: %v", p)
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
	psrc := &PrintingConn{conn: src}
	pdst := &PrintingConn{conn: dst}
	errc := make(chan error, 1)
	go copyPayload(errc, psrc, pdst)
	go copyPayload(errc, pdst, psrc)

	// Blocks until the first error / EOF.
	<-errc
}

func copyPayload(errc chan<- error, src, dst *PrintingConn) {
	_, err := io.Copy(dst, src)
	if err != nil {
		log.Printf("io.Copy from %s to %s returned with error: %v", src.conn.RemoteAddr(), dst.conn.RemoteAddr(), err)
	}
	errc <- err
}

func main() {
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*sslCert, *sslCertKey)
	if err != nil {
		log.Fatal(err)
	}
	tlsconf := &tls.Config{Certificates: []tls.Certificate{cert}}

	smtp, err := tls.Listen("tcp4", fmt.Sprintf(":%d", SmtpPublicPort), tlsconf)
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
