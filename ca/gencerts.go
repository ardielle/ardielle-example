package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

//generate the keys and certs used by the example
func main() {
	createAuthority()
	createCert("contacts", "Example contacts service", "keys/contacts.key", "certs/contacts.cert")
	createCert("client", "Example contacts client", "keys/client.key", "certs/client.cert")
}

const caKeyFile = "keys/ca.key"
const caCertFile = "certs/ca.cert"

func createAuthority() {
	//   1. create private key for ca
	caKey, err := GenerateKeyPair()
	if err != nil {
		fatal("Cannot generate private key: %v\n", err)
	}
	//   2. create self-signed cert
	country := "US"
	province := "Oregon"
	locality := "Stafford"
	org := "Ardielle"
	unit := "Example Certificate Authority"
	name := "Example CA"
	caCertPem, err := CreateCACert(caKey, country, locality, province, org, unit, name, nil, nil)
	if err != nil {
		fatal("Cannot create CA Cert: %v\n", err)
	}
	caKeyPem := PrivatePem(caKey)

	//   3. store ca.cert.pem and ca.key.pem into local files in case we need to re-upload
	os.MkdirAll("keys", 0700)
	os.MkdirAll("certs", 0755)
	ioutil.WriteFile(caKeyFile, []byte(caKeyPem), 0600)
	ioutil.WriteFile(caCertFile, []byte(caCertPem), 0644)
}

func createCert(name, descr, keyFile, certFile string) {
	key, err := GenerateKeyPair()
	if err != nil {
		fatal("Cannot generate private key: %v\n", err)
	}
	ip := "127.0.0.1"
	hostname := "localhost"
	csr, err := GenerateCSR(key, "US", "OR", "Stafford", "Ardielle", descr, name, ip, hostname)
	if err != nil {
		fatal("Cannot generate CSR")
	}

	//now sign it
	pem, err := GenerateCert(csr, caKeyFile, caCertFile, name)
	if err != nil {
		fatal("Cannot generate cert")
	}

	//everything ok. So, write the key and cert files
	keyPem := PrivatePem(key)
	err = ioutil.WriteFile(keyFile, []byte(keyPem), 0400)
	if err != nil {
		fatal("Cannot write key file: %s\n", keyFile)
	}
	err = ioutil.WriteFile(certFile, []byte(pem), 0444)
	if err != nil {
		fatal("Cannot write cert file")
	}

}

func fatal(msg string, args ...interface{}) {
	s := fmt.Sprintf(msg, args...)
	fmt.Printf("*** %s\n", s)
	os.Exit(1)
}

func GenerateKeyPair() (*rsa.PrivateKey, error) {
	//import crypto/elliptic
	//ideally, use ECDSA-384
	//return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	return rsa.GenerateKey(rand.Reader, 2048) //4096 for CAs is preferred
}

func PrivatePem(privateKey *rsa.PrivateKey) string {
	privatePem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	privateBytes := pem.EncodeToMemory(privatePem)
	return string(privateBytes)
}

func CreateCACert(key *rsa.PrivateKey, country, locality, province, org, unit, cn string, hosts []string, ips []net.IP) (string, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", err
	}
	//algo := x509.SHA256WithRSA //for ecdsa
	algo := x509.SHA1WithRSA //for rsa
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)
	subj := pkix.Name{
		CommonName:         cn,
		Country:            []string{country},
		Locality:           []string{locality},
		Province:           []string{province},
		Organization:       []string{org},
		OrganizationalUnit: []string{unit},
	}

	template := &x509.Certificate{
		Subject:            subj,
		SerialNumber:       serialNumber,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          key.PublicKey,
		SignatureAlgorithm: algo,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		//		EmailAddresses:        csr.EmailAddresses,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		//		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}
	if hosts != nil {
		template.DNSNames = hosts
	}
	if ips != nil {
		template.IPAddresses = ips
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	certOut := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return "", fmt.Errorf("Cannot encode Cert to PEM: %v", err)
	}
	return certOut.String(), nil
}

func GenerateCSR(key *rsa.PrivateKey, country, province, locality, org, orgUnit, commonName, ip, host string) (string, error) {
	//note: RFC 6125 states that if the SAN (Subject Alternative Name) exists, it is used, not the CA. So, we will
	//always put the Athens name in the CN (it is *not* a DNS domain name), and put the host name into the SAN.
	subj := pkix.Name{CommonName: commonName}
	if country != "" {
		subj.Country = []string{country}
	}
	if org != "" {
		subj.Organization = []string{org}
	}
	if orgUnit != "" {
		subj.OrganizationalUnit = []string{orgUnit}
	}
	if locality != "" {
		subj.Locality = []string{locality}
	}
	if province != "" {
		subj.Province = []string{province}
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA1WithRSA,
		// Attributes: ??
		// Extensions: ??
		// EmailAddresses:     []string{"gopher@golang.org"},
	}
	if ip != "" {
		template.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	if host != "" {
		template.DNSNames = []string{host}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return "", fmt.Errorf("Cannot create CSR: %v", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, block)
	if err != nil {
		return "", fmt.Errorf("Cannot encode CSR to PEM: %v", err)
	}
	return buf.String(), nil
}

func GenerateCert(csrPem, caKeyFile, caCertFile, cn string) (string, error) {
	caCertPemBytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return "", err
	}
	caCert, err := CertFromPEMBytes(caCertPemBytes)
	if err != nil {
		return "", err
	}
	caKey, err := PrivateKeyFromFile(caKeyFile)
	if err != nil {
		return "", err
	}
	return GenerateCertInMemory(csrPem, caKey, caCert, cn)
}

func CertFromPEMBytes(pemBytes []byte) (*x509.Certificate, error) {
	var derBytes []byte
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("Cannot parse cert (empty pem)")
	}
	derBytes = block.Bytes
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
func PrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromPemBytes(pemBytes)
}
func PublicKeyFromPemBytes(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsaPub, nil
}
func GenerateCertInMemory(csrPem string, caKey *rsa.PrivateKey, caCert *x509.Certificate, cn string) (string, error) {
	csr, err := decodeCSR(csrPem)
	if err != nil {
		return "", err
	}
	if cn != "" && cn != csr.Subject.CommonName {
		return "", fmt.Errorf("CSR common name (%s) doesn't match expected common name (%s)", csr.Subject.CommonName, cn)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	algo := x509.SHA256WithRSA
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour //fixme
	notAfter := notBefore.Add(validFor)
	template := &x509.Certificate{
		Subject:               csr.Subject,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SignatureAlgorithm:    algo,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return "", err
	}

	certOut := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err != nil {
		return "", fmt.Errorf("Cannot encode Cert to PEM: %v", err)
	}
	return certOut.String(), nil
}
func PrivateKeyFromPemBytes(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
func decodeCSR(csr string) (*x509.CertificateRequest, error) {
	var derBytes []byte
	block, _ := pem.Decode([]byte(csr))
	if block == nil {
		return nil, fmt.Errorf("Cannot parse CSR (empty pem)")
	}
	derBytes = block.Bytes
	req, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, err
	}
	//err = req.CheckSignatureFrom(parent)
	err = req.CheckSignature()
	if err != nil {
		return nil, err
	}
	return req, nil
}
