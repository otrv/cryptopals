package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

func fixedXor(a []byte, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("size mismatch")
	}

	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}

	return res, nil
}

func maxFloat64(arr []float64) int {
	maxIndex := 0
	maxValue := 0.0
	for i, score := range arr {
		if score > maxValue {
			maxValue = score
			maxIndex = i
		}
	}

	return maxIndex
}

func scoreEnglishness(in []byte) float64 {
	letterScores := map[byte]float64{
		'A': 8.167,
		'B': 1.492,
		'C': 2.782,
		'D': 4.253,
		'E': 12.702,
		'F': 2.228,
		'G': 2.015,
		'H': 6.094,
		'I': 6.966,
		'J': 0.153,
		'K': 0.772,
		'L': 4.025,
		'M': 2.406,
		'N': 6.749,
		'O': 7.507,
		'P': 1.929,
		'Q': 0.095,
		'R': 5.987,
		'S': 6.327,
		'T': 9.056,
		'U': 2.758,
		'V': 0.978,
		'W': 2.360,
		'X': 0.150,
		'Y': 1.974,
		'Z': 0.074,
		' ': 15.000,
	}

	score := 0.0

	for _, ch := range in {
		if ch >= byte('a') && ch <= byte('z') {
			ch = ch - 32
		}

		val, ok := letterScores[ch]
		if ok {
			score += val
		} else if ch < 32 || ch > 126 {
			score -= 20
		}
	}

	return score
}

func findMostEnglish(in [][]byte) int {
	scores := make([]float64, len(in))
	for idx, candidate := range in {
		scores[idx] = scoreEnglishness(candidate)
	}

	idx := maxFloat64(scores[:])

	return idx
}

func decryptSingleByteXor(in []byte) []byte {
	var candidates [256][]byte
	for i := range 255 {
		b := bytes.Repeat([]byte{byte(i)}, len(in))

		candidate, err := fixedXor(in, b)
		if err != nil {
			panic(err)
		}
		candidates[i] = candidate
	}

	idx := findMostEnglish(candidates[:])

	return candidates[idx]
}

func main() {
	file, err := os.ReadFile("./input.txt")
	if err != nil {
		panic(err)
	}

	file = bytes.TrimRight(file, "\n")

	cypher := make([]byte, len(file))
	for i := range len(file) {
		switch i % 3 {
		case 0:
			cypher[i] = 'I'
		case 1:
			cypher[i] = 'C'
		case 2:
			cypher[i] = 'E'
		}
	}

	encrypted, err := fixedXor(file, cypher)
	if err != nil {
		panic(err)
	}

	fmt.Println("Original Input Len:", len(file))
	fmt.Println("Cypher:            ", string(cypher))
	fmt.Println("Cypher Len:        ", len(cypher))
	fmt.Println("Encrypted Len:     ", len(encrypted))
	fmt.Println("Encrypted:         ", hex.EncodeToString(encrypted))
}
