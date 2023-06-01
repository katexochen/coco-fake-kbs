package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

var privateKey *rsa.PrivateKey

func main() {
	listen := flag.String("listen", ":8080", "listen address")
	flag.Parse()

	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// print the public key
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
		},
	)
	log.Println("server's public key:")
	fmt.Println(string(pemdata))

	r := mux.NewRouter()
	r.HandleFunc("/kbs/v0/resource/{repository}/{type}/{tag}", GetResourceHandler)
	r.HandleFunc("/kbs/v0/auth", AuthHandler)
	r.HandleFunc("/kbs/v0/attest", AttestHandler)
	r.HandleFunc("/kbs/v0/attestation-policy", AttestationPolicyHandler)
	r.HandleFunc("/kbs/v0/token-certificate-chain", TokenCertificateCainHandler)

	log.Printf("listening on %s\n", *listen)
	log.Fatal(http.ListenAndServe(*listen, r))
}

func GetResourceHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("GetResourceHandler called")
	log.Printf("cookie: %q\n", r.Header.Get("Cookie"))

	vars := mux.Vars(r)
	repository := vars["repository"]
	resourceType := vars["type"]
	tag := vars["tag"]
	log.Printf("repository: %q, type: %q, tag: %q\n", repository, resourceType, tag)

	w.Header().Set("Content-Type", "application/json")
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("AuthHandler called")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	log.Printf("body: %s\n", string(body))

	challenge := Challenge{
		Nonce: "5555",
	}
	w.Header().Set("Set-Cookie", "kbs-session-id=123")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(challenge); err != nil {
		panic(err)
	}
}

func AttestHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("AttestHandler called")
	log.Printf("cookie: %q\n", r.Header.Get("Cookie"))
	body, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	log.Printf("body: %s\n", string(body))

	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.MapClaims{
			"exp":        time.Now().Add(time.Hour * 72).Unix(),
			"iat":        time.Now().Unix(),
			"iss":        "coco-fake-kbs",
			"tee-pubkey": "foo",
		},
	)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	log.Println("answering with token:")
	fmt.Println(tokenString)

	if _, err := w.Write([]byte(tokenString)); err != nil {
		panic(err)
	}
}

func AttestationPolicyHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("PolicyHandler called")
	log.Printf("cookie: %q\n", r.Header.Get("Cookie"))
	body, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	log.Printf("body: %s\n", string(body))

	w.Header().Set("Content-Type", "application/json")
}

func TokenCertificateCainHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("TokenCertificateCainHandler called")
	log.Printf("cookie: %q\n", r.Header.Get("Cookie"))

	w.Header().Set("Content-Type", "application/json")
}

type Request struct {
	Version     string `json:"version"`
	TEE         string `json:"tee"`
	ExtraParams string `json:"extra-params"`
}

type Challenge struct {
	Nonce       string `json:"nonce"`
	ExtraParams string `json:"extra-params"`
}

type Attestation struct {
	TEEPubKey   string `json:"tee-pubkey"`
	TEEEvidence string `json:"tee-evidence"`
}

type Response struct { // jwt...
	Protected    string `json:"protected"`
	EncryptedKey string `json:"encrypted_key"`
	IV           string `json:"iv"`
	Ciphertext   string `json:"ciphertext"`
	Tag          string `json:"tag"`
}
