package xmlsig

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/moov-io/signedxml"
)

func TestExample(t *testing.T) {

	// laoding private key and certificate
	cert, err := tls.LoadX509KeyPair("cert.pem", "demo.key")
	if err != nil {
		t.Error("Error on loading certificate")
		return
	}

	// here is the document that we need to sign
	doc := Test1{
		Data: "Hello, World!",
		ID:   "_1234",
	}

	// creating new singer object
	signer, err := NewSigner(cert)
	if err != nil {
		t.Error("Error on creating signer")
		return
	}

	// creating digital signature
	sig, err := signer.CreateSignature(doc, doc.ID)
	if err != nil {
		t.Error("can't create signature")
		return
	}
	doc.Signature = sig

	// converting struct to xml
	var signedDoc bytes.Buffer

	encoder := xml.NewEncoder(&signedDoc)
	err = encoder.Encode(doc)
	if err != nil {
		t.Error("can't encode signed XML doc")
		return
	}

	encoder.Flush()
	s := signedDoc.String()

	// verifying digital signature
	validator, err := signedxml.NewValidator(s)
	if err != nil {
		t.Error("can't create signed XML validator")
		return
	}

	_, err = validator.ValidateReferences()
	if err != nil {
		t.Error("signature verification failed:", err)
	}

	// changing digitally signed content
	s = strings.Replace(s, "World!", "world!", -1)

	// verifying digital signature
	validator, err = signedxml.NewValidator(s)
	if err != nil {
		t.Error("can't create new signed XML validator")
		return
	}

	// this time digital signature must be invalid
	_, err = validator.ValidateReferences()
	if err == nil {
		t.Error("signature verification failed (signed content is modified):", err)
	}

}

type Test1 struct {
	XMLName   xml.Name `xml:"urn:envelope Envelope"`
	ID        string   `xml:",attr"`
	Data      string   `xml:"urn:envelope Data"`
	Signature *Signature
}
