package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"
)

func main() {
	fmt.Println(run())
}

type fakeSigner struct {
	crypto.Signer
}

func (s *fakeSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	k := s.Public().(*rsa.PublicKey).Size()
	return make([]byte, k), nil
}

func generateBigRSA(size int) *rsa.PrivateKey {
	b := make([]byte, size)
	b[0] = 0xf3
	return &rsa.PrivateKey{PublicKey: rsa.PublicKey{
		N: big.NewInt(0).SetBytes(b),
		E: 0b100001,
	}}
}

func run() error {
	certPEM, err := os.ReadFile("./ca.pem")
	if err != nil {
		return err
	}

	pCert, _ := pem.Decode(certPEM)

	cert, err := x509.ParseCertificate(pCert.Bytes)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	if os.Args[1] == "client" {
		c, err := tls.Dial("tcp", "localhost:8888", &tls.Config{RootCAs: pool})
		if err != nil {
			return err
		}
		defer c.Close()

		err = c.Handshake()
		if err != nil {
			return err
		}
		return nil
	} else if os.Args[1] == "client-auth" {
		rsa := generateBigRSA(1024 * 63)
		clientCertRaw, err := makeCert("./ca.pem", "./ca-key.pem", pkix.Name{CommonName: "localhost"}, []string{"localhost"}, rsa.Public())
		if err != nil {
			return err
		}

		var clientCert = tls.Certificate{
			Certificate: [][]byte{clientCertRaw},
			PrivateKey:  &fakeSigner{rsa},
		}

		c, err := tls.Dial("tcp", "localhost:8889", &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{clientCert}})
		if err != nil {
			return err
		}
		defer c.Close()

		err = c.Handshake()
		if err != nil {
			return err
		}
		c.Read(make([]byte, 1))
		return nil
	} else {
		go func() {
			rsa, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}

			c, err := makeCert("./ca.pem", "./ca-key.pem", pkix.Name{CommonName: "localhost"}, []string{"localhost"}, rsa.Public())
			if err != nil {
				panic(err)
			}

			var cert = tls.Certificate{
				Certificate: [][]byte{c},
				PrivateKey:  rsa,
			}

			l, err := tls.Listen("tcp", "localhost:8889", &tls.Config{ClientCAs: pool, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert})
			if err != nil {
				panic(err)
			}

			for {
				con, err := l.Accept()
				if err != nil {
					fmt.Println(err)
					continue
				}
				go func() {
					err = con.(*tls.Conn).Handshake()
					con.Write(make([]byte, 1))
					fmt.Println(err)
					con.Close()
				}()
			}
		}()

		rsa := generateBigRSA(1024 * 63)
		c, err := makeCert("./ca.pem", "./ca-key.pem", pkix.Name{CommonName: "localhost"}, []string{"localhost"}, rsa.Public())
		if err != nil {
			return err
		}

		var cert = tls.Certificate{
			Certificate: [][]byte{c},
			PrivateKey:  &fakeSigner{rsa},
		}

		l, err := tls.Listen("tcp", "localhost:8888", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			return err
		}

		for {
			con, err := l.Accept()
			if err != nil {
				fmt.Println(err)
				continue
			}
			go func() {
				err = con.(*tls.Conn).Handshake()
				con.Write(make([]byte, 1))
				fmt.Println(err)
				con.Close()
			}()
		}
	}
}

func makeCert(caCertPath, caKeyPath string, subject pkix.Name, dnsNames []string, public any) ([]byte, error) {
	intCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	intKeyPem, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, err
	}
	pIntCert, _ := pem.Decode(intCertPEM)
	pIntKey, _ := pem.Decode(intKeyPem)

	key, err := x509.ParsePKCS8PrivateKey(pIntKey.Bytes)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(pIntCert.Bytes)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 16)
	buf2 := make([]byte, 16)
	rand.Read(buf)
	rand.Read(buf2)

	newCert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SubjectKeyId:          buf,
		AuthorityKeyId:        cert.SubjectKeyId,
		SerialNumber:          big.NewInt(0).SetBytes(buf2),
		Subject:               subject,
		DNSNames:              dnsNames,
		BasicConstraintsValid: true,
		IsCA:                  false,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 50),
	}, cert, public, key)
	if err != nil {
		return nil, err
	}

	return newCert, nil
}
