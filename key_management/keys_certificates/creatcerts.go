package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	count := 0
	for {
		count++
		certFileName := fmt.Sprintf("node_%d.crt", count)
		keyFileName := fmt.Sprintf("node_%d.key", count)
		if _, err := os.Stat(certFileName); err == nil {
			// 文件已存在，继续循环递增num
			continue
		} else if !os.IsNotExist(err) {
			fmt.Println("Error checking file existence:", err)
			return
		}
		// 证书文件不存在，创建新文件
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		publicKey := privateKey.PublicKey

		template := x509.Certificate{
			SerialNumber: big.NewInt(int64(count)),
			Subject:      pkix.Name{CommonName: fmt.Sprintf("Node %d", count)},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0), // Expires in one year
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &publicKey, privateKey)
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return
		}

		certOut, err := os.Create(certFileName)
		if err != nil {
			fmt.Println("Failed to create certificate file:", err)
			return
		}
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		certOut.Close()

		keyOut, err := os.OpenFile(keyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Println("Failed to open key file:", err)
			return
		}
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
		keyOut.Close()

		fmt.Printf("Created files: %s, %s\n", certFileName, keyFileName)
		break
	}
}
