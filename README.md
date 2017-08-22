I wrote this to sign XML documents produced by using Go's default XML encoder. It's not capable of signing arbitrary XML. The following example shows how to produce a simple signature.

import (
	"crypto/tls"
	"encoding/xml"
	"os"

	"github.com/amdonov/xmlsig"
)

func example() error {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		return err
	}
	signer, err := xmlsig.NewSigner(cert)
	if err != nil {
		return err
	}
	doc := Test1{
		Data: "Hello, World!",
		ID:   "_1234",
	}
	sig, err := signer.CreateSignature(doc)
	if err != nil {
		return err
	}
	doc.Signature = sig
	encoder := xml.NewEncoder(os.Stdout)
	return encoder.Encode(doc)
}

type Test1 struct {
	XMLName   xml.Name `xml:"urn:envelope Envelope"`
	ID        string   `xml:",attr"`
	Data      string   `xml:"urn:envelope Data"`
	Signature *xmlsig.Signature
}
