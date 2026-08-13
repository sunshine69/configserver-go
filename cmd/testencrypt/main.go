package main

import (
	"fmt"
	u "github.com/sunshine69/golang-tools/utils"
)

func main() {
	testCases := []string{
		`p@ss"w0rd`,
		`p's'w'o'r'd`,
		`line1|newline2`,
		`: key: value # comment > - ?`,
	}

	for _, plaintext := range testCases {
		fmt.Printf("\nOriginal plaintext: %q\n", plaintext)

		// Encrypt
		ciphertext, err := u.Encrypt(plaintext, "testkey", nil)
		if err != nil {
			fmt.Printf("  ERROR encrypting: %v\n", err)
			continue
		}
		fmt.Printf("  Ciphertext: %q\n", ciphertext)

		// Decrypt
		decrypted, err := u.Decrypt(ciphertext, "testkey", nil)
		if err != nil {
			fmt.Printf("  ERROR decrypting: %v\n", err)
			continue
		}
		fmt.Printf("  Decrypted:  %q (match: %v)\n", decrypted, decrypted == plaintext)
	}
}
