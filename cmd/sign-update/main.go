package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

type manifest struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
	Notes     string `json:"notes,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("用法：sign-update keygen | sign <private-key-file> <version> <binary-url> <binary-file> [notes]")
	}
	switch os.Args[1] {
	case "keygen":
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile("kunpanel-update-private.key", []byte(base64.StdEncoding.EncodeToString(private)), 0600); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile("kunpanel-update-public.key", []byte(base64.StdEncoding.EncodeToString(pub)), 0644); err != nil {
			log.Fatal(err)
		}
		fmt.Println("已生成私钥 kunpanel-update-private.key 和公钥 kunpanel-update-public.key")
	case "sign":
		if len(os.Args) < 6 {
			log.Fatal("参数不足")
		}
		keyText, err := os.ReadFile(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		private, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyText)))
		if err != nil || len(private) != ed25519.PrivateKeySize {
			log.Fatal("私钥格式无效")
		}
		binary, err := os.ReadFile(os.Args[5])
		if err != nil {
			log.Fatal(err)
		}
		sum := sha256.Sum256(binary)
		item := manifest{Version: os.Args[3], URL: os.Args[4], SHA256: hex.EncodeToString(sum[:])}
		if len(os.Args) > 6 {
			item.Notes = os.Args[6]
		}
		message := item.Version + "\n" + item.URL + "\n" + item.SHA256
		item.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(private), []byte(message)))
		out, _ := json.MarshalIndent(item, "", "  ")
		fmt.Println(string(out))
	default:
		log.Fatal("未知命令")
	}
}
