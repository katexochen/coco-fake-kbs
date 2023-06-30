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

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

func main() {
	listen := flag.String("listen", ":8080", "listen address")
	flag.Parse()

	server := NewServer()
	log.Fatal(server.Serve(*listen))
}

type server struct {
	teePubKeys map[string]*jose.JSONWebKey
	privKey    *rsa.PrivateKey
}

func NewServer() *server {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
		},
	)
	log.Println("server's public key:")
	fmt.Println(string(pemdata))

	return &server{
		teePubKeys: make(map[string]*jose.JSONWebKey),
		privKey:    privateKey,
	}
}

func (s *server) Serve(listen string) error {
	r := mux.NewRouter()
	r.HandleFunc("/kbs/v0/resource/{repository}/{type}/{tag}", s.GetResourceHandler)
	r.HandleFunc("/kbs/v0/auth", s.AuthHandler)
	r.HandleFunc("/kbs/v0/attest", s.AttestHandler)
	r.HandleFunc("/kbs/v0/attestation-policy", s.AttestationPolicyHandler)
	r.HandleFunc("/kbs/v0/token-certificate-chain", s.TokenCertificateCainHandler)

	log.Printf("listening on %s\n", listen)
	return http.ListenAndServe(listen, r)
}

func (s *server) GetResourceHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("GetResourceHandler called")
	cookie := r.Header.Get("Cookie")
	log.Printf("cookie: %q\n", cookie)

	vars := mux.Vars(r)
	repository := vars["repository"]
	resourceType := vars["type"]
	tag := vars["tag"]
	log.Printf("repository: %q, type: %q, tag: %q\n", repository, resourceType, tag)

	teePubKey, ok := s.teePubKeys[cookie]
	if !ok {
		panic("no tee key found")
	}

	recipient := jose.Recipient{Algorithm: jose.RSA_OAEP, Key: teePubKey}
	encrypter, err := jose.NewEncrypter(jose.A128GCM, recipient, nil)
	if err != nil {
		panic(err)
	}
	plaintext := []byte("Lorem ipsum dolor sit amet")
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}
	serialized := object.FullSerialize()

	if _, err := w.Write([]byte(serialized)); err != nil {
		panic(err)
	}
}

func (s *server) AuthHandler(w http.ResponseWriter, r *http.Request) {
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

func (s *server) AttestHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("AttestHandler called")
	cookie := r.Header.Get("Cookie")
	log.Printf("cookie: %q\n", cookie)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	log.Printf("body: %s\n", string(body))

	var req Attestation
	if err := json.Unmarshal(body, &req); err != nil {
		panic(err)
	}

	if !req.TEEPubKey.Valid() {
		panic("invalid tee pubkey")
	}
	s.teePubKeys[cookie] = &req.TEEPubKey

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
	tokenString, err := token.SignedString(s.privKey)
	if err != nil {
		panic(err)
	}

	log.Println("answering with token:")
	fmt.Println(tokenString)

	if _, err := w.Write([]byte(tokenString)); err != nil {
		panic(err)
	}
}

func (s *server) AttestationPolicyHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("PolicyHandler called")
	log.Printf("cookie: %q\n", r.Header.Get("Cookie"))
	body, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	log.Printf("body: %s\n", string(body))

	w.Header().Set("Content-Type", "application/json")
}

func (s *server) TokenCertificateCainHandler(w http.ResponseWriter, r *http.Request) {
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
	TEEPubKey   jose.JSONWebKey `json:"tee-pubkey"`
	TEEEvidence string          `json:"tee-evidence"`
}

type Response struct { // jwt...
	Protected    string `json:"protected"`
	EncryptedKey string `json:"encrypted_key"`
	IV           string `json:"iv"`
	Ciphertext   string `json:"ciphertext"`
	Tag          string `json:"tag"`
}
