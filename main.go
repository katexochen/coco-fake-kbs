package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	listen := flag.String("listen", ":8080", "listen address")

	r := mux.NewRouter()
	r.HandleFunc("/kbs/v0/resource/{repository}/{type}/{tag}", GetResourceHandler)
	r.HandleFunc("/kbs/v0/auth", AuthHandler)
	r.HandleFunc("/kbs/v0/attest", AttestHandler)
	r.HandleFunc("/kbs/v0/attestation-policy", AttestationPolicyHandler)
	r.HandleFunc("/kbs/v0/token-certificate-chain", TokenCertificateCainHandler)

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

	w.Header().Set("Content-Type", "application/json")
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
	Version string `json:"version"`
	TEE     string `json:"tee"`
	// ExtraParams ? `json:"extra-parama"`
}

type Challenge struct {
	Nonce string `json:"nonce"`
	// ExtraParams ? `json:"extra-params"`
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
