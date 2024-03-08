package utility

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AES256Decrypt decrypts the given data using AES-256 encryption algorithm.
// It takes the encrypted data, encryption key, and initial vector as input.
func AES256Decrypt(data []byte, key []byte, initialVector []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(initialVector) != aes.BlockSize {
		return nil, fmt.Errorf("initialVector length mismatch, must be %d, not %d",
			aes.BlockSize, len(initialVector))
	}

	blockCipherMode := cipher.NewCBCDecrypter(block, initialVector)
	return PerformBlockCipherOperation(blockCipherMode, data)
}

// PerformBlockCipherOperation performs the block cipher operation using the given block cipher mode and data.
func PerformBlockCipherOperation(blockCipherMode cipher.BlockMode, data []byte) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data length must be a multiple of %d", aes.BlockSize)
	}

	result := make([]byte, len(data))
	blockCipherMode.CryptBlocks(result, data)
	return result, nil
}
