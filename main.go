package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strconv"
	"time"
)

var PrvKey *rsa.PrivateKey
var PubKey *rsa.PublicKey

func init() {
	PrvKey, PubKey = generateKey(4096)

}

func main() {
	r := gin.Default()
	r.GET("/", think)
	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

func think(c *gin.Context) {
	timestamp := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	signature, err := generateSignature(timestamp, PrvKey)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	err = verifySignature(timestamp, signature, PubKey)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.String(http.StatusOK, timestamp)
}

func generateKey(size int) (prvKey *rsa.PrivateKey, pubKey *rsa.PublicKey) {
	prvKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		log.Fatalln(err)
	}
	pubKey = &prvKey.PublicKey
	return
}

func generateSignature(message string, prvKey *rsa.PrivateKey) (signature string, err error) {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto

	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write([]byte(message))
	hashed := pssh.Sum(nil)
	signatureByte, err := rsa.SignPSS(
		rand.Reader,
		prvKey,
		newhash,
		hashed,
		&opts,
	)
	signature = string(signatureByte)
	return
}

func verifySignature(message, signature string, pubKey *rsa.PublicKey) (err error) {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto

	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write([]byte(message))
	hashed := pssh.Sum(nil)
	err = rsa.VerifyPSS(
		pubKey,
		newhash,
		hashed,
		[]byte(signature),
		&opts,
	)
	return
}
