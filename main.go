package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
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

func chi2(observed float64, expected float64) float64 {
	diff := float64(observed) - expected
	return (diff * diff) / expected
}

// minFloat64 return the minimum value and its index from an array of float64
func minFloat64(arr []float64) (float64, int) {
	minValue := arr[0]
	minIndex := 0
	for i, score := range arr {
		if score < minValue {
			minValue = score
			minIndex = i
		}
	}

	return minValue, minIndex
}

// determineEnglishness determine how closer a given sequence of byte to plaintext english. Lower is better
func determineEnglishness(in []byte) float64 {
	engFreqs := [27]float64{
		0.0651738, 0.0124248, 0.0217339, 0.0349835,
		0.1041442, 0.0197881, 0.0158610, 0.0492888,
		0.0558094, 0.0009033, 0.0050529, 0.0331490,
		0.0202124, 0.0564513, 0.0596302, 0.0137645,
		0.0008606, 0.0497563, 0.0515760, 0.0729357,
		0.0225134, 0.0082903, 0.0171272, 0.0013692,
		0.0145984, 0.0007836, 0.1918182,
	}

	var occurences [27]int
	validSize := 0

	for _, ch := range in {
		if ch == byte(' ') {
			occurences[26]++ // 26 is space
			validSize++
		} else if ch >= byte('A') && ch <= byte('Z') {
			occurences[ch-byte('A')]++
			validSize++
		} else if ch >= byte('a') && ch <= byte('z') {
			occurences[ch-32-byte('A')]++
			validSize++
		}
	}

	if validSize == 0 {
		return math.Inf(1)
	}

	var score float64 = 0
	for i, observed := range occurences {
		expected := float64(validSize) * engFreqs[i]
		score += chi2(float64(observed), expected)
	}

	return score
}

func decryptSingleByteXor(in []byte) []byte {
	var candidates [255][]byte
	for i := range 255 {
		b := bytes.Repeat([]byte{byte(i)}, len(in))

		candidate, err := fixedXor(in, b)
		if err != nil {
			panic(err)
		}
		candidates[i] = candidate
	}

	var scores [255]float64
	for idx, candidate := range candidates {
		scores[idx] = determineEnglishness(candidate)
	}

	_, idx := minFloat64(scores[:])

	return candidates[idx]
}

func main() {
	crypted, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(decryptSingleByteXor(crypted)))
}
