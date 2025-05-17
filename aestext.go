package aestext

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
)

func EncText(dataToEncrypt string, encryptionKey string) string {

	data := dataToEncrypt
	dataByte := []byte(data)
	aesKey := encryptionKey

	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		log.Fatal("error creating aes block cipher\n", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("error setting Galois/Counter Mode (GCM)\n", err)
	}

	numberOnce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, numberOnce); err != nil {
		log.Fatal("error generating the number once value\n", err)
	}

	cipherText := gcm.Seal(numberOnce, numberOnce, dataByte, nil)
	encryptedString := hex.EncodeToString(cipherText)

	return encryptedString
}

func DecText(dataToDecrypt string, decryptionKey string) string {

	encryptedString, err := hex.DecodeString(dataToDecrypt)
	if err != nil {
		log.Fatal("error decoding string\n", err)
	}

	aesKey := decryptionKey

	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		log.Fatal("error creating aes block cipher\n", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("error setting Galois/Counter Mode (GCM)\n", err)
	}

	numberOnceSize := gcm.NonceSize()
	numberOnce := encryptedString[:numberOnceSize]
	ciphertext := encryptedString[numberOnceSize:]

	decryptedString, err := gcm.Open(nil, []byte(numberOnce), []byte(ciphertext), nil)
	if err != nil {
		log.Fatal("error decrypting\n", err)
	}

	return string(decryptedString)
}
