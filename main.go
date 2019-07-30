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
)

const (
	SmtpPublicPort = 587
	ImapPublicPort = 993
)

func acceptConnections(l net.Listener, handler func(net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			log.Println(err)
			return
		}
		defer c.Close()
		log.Printf("Client: %s connected to %s.", c.RemoteAddr(), c.LocalAddr())
		handler(c)
	}
}

func handleImapConnection(c net.Conn) {
	forwardTraffic(c, fmt.Sprintf("%s:%d", *mailBackendAddr, imapPrivatePort))
}

func handleSmptConnection(c net.Conn) {
	forwardTraffic(c, fmt.Sprintf("%s:%d", *mailBackendAddr, smtpPrivatePort))
}

func forwardTraffic(src net.Conn, dstaddr string) {
	dst, err := net.Dial("tcp", dstaddr)
	if err != nil {
		log.Printf("Unable to connect to mail backend: %s, err: %v", *mailBackendAddr, err)
		return
	}
	defer dst.Close()

	log.Printf("Forwarding traffic from %s to %s.", src.RemoteAddr(), dst.RemoteAddr())
	errc := make(chan error, 1)
	go copyPayload(errc, src, dst)
	go copyPayload(errc, dst, src)

	// Blocks until the first error / EOF.
	<-errc
}

func copyPayload(errc chan<- error, src, dst net.Conn) {
	_, err := io.Copy(dst, src)
	errc <- err
}

func main() {
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

	imap, err := tls.Listen("tcp4", fmt.Sprintf(":%d", ImapPublicPort), tlsconf)
	if err != nil {
		log.Fatal(err)
	}
	defer imap.Close()

	donec := make(chan bool, 1)
	go acceptConnections(smtp, handleSmptConnection)
	go acceptConnections(imap, handleImapConnection)
	<-donec
}
