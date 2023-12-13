package main

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	var derPath string
	var pemPath string
	flag.StringVar(&derPath, "der", "", "file path in DER format")
	flag.StringVar(&pemPath, "pem", "", "file path in PEM format")
	flag.Parse()

	if len(derPath) == 0 && len(pemPath) == 0 {
		fmt.Fprintln(os.Stderr, "No certificate file path in any format specified (DER or PEM)")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var derContent []byte
	if len(pemPath) > 0 {
		content, err := parsePem(pemPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse PEM error: %v", err)
			os.Exit(1)
		}
		derContent = content
	} else {
		content, err := os.ReadFile(derPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "DER format decode error: %v\n", err)
			os.Exit(1)
		}
		derContent = content
	}

	r, err := subjectMd5Of(derContent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ParseCertificate error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%08x\n", r)
}

func parsePem(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(content)
	if block == nil {
		return nil, errors.New("pem decode error")
	}
	return block.Bytes, nil
}

func subjectMd5Of(content []byte) (r uint64, err error) {
	certificate, err := x509.ParseCertificate(content)
	if err != nil {
		return 0, err
	}
	if len(certificate.RawSubject) == 0 {
		return 0, errors.New("no raw subject")
	}
	md := md5.Sum(certificate.RawSubject)
	r = (uint64(md[0]) | (uint64(md[1]) << 8) | (uint64(md[2]) << 16) | (uint64(md[3]) << 24)) & 0xffffffff
	return
}
