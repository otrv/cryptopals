package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
)

func FixedXor(a []byte, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("fixed xor size mismatch")
	}

	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}

	return res, nil
}

func MaxFloat64(arr []float64) int {
	maxIndex := 0
	maxValue := 0.0
	for i, val := range arr {
		if val > maxValue {
			maxValue = val
			maxIndex = i
		}
	}

	return maxIndex
}

func MinFloat64(arr []float64) int {
	minIndex := 0
	minValue := math.MaxFloat64
	for i, val := range arr {
		if val < minValue {
			minValue = val
			minIndex = i
		}
	}

	return minIndex
}

var englishLetterScores map[byte]float64 = map[byte]float64{
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

func TopEnglishIndex(in [][]byte) int {
	scores := make([]float64, len(in))
	for idx, candidate := range in {
		score := 0.0

		for _, ch := range candidate {
			if ch >= byte('a') && ch <= byte('z') {
				ch = ch - 32
			}

			val, ok := englishLetterScores[ch]
			if ok {
				score += val
			} else if ch < 32 || ch > 126 {
				score -= 20
			}
		}
		scores[idx] = score
	}

	idx := MaxFloat64(scores[:])

	return idx
}

// DecryptSingleByteXor decrypts the input with a single byte xor. Returns the decrypted value and the key.
func DecryptSingleByteXor(in []byte) ([]byte, byte) {
	var candidates [256][]byte
	for i := range 255 {
		b := bytes.Repeat([]byte{byte(i)}, len(in))

		candidate, err := FixedXor(in, b)
		if err != nil {
			panic(err)
		}
		candidates[i] = candidate
	}

	idx := TopEnglishIndex(candidates[:])

	return candidates[idx], byte(idx)
}

func RepeatingKeyXor(in []byte, key []byte) ([]byte, error) {
	cypher := make([]byte, len(in))
	for i := range len(in) {
		cypher[i] = key[i%len(key)]
	}

	res, err := FixedXor(in, cypher)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func HammingDistance(a []byte, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, errors.New("len mismatch")
	}

	distance := 0
	for i := range a {
		xor := a[i] ^ b[i]
		for xor != 0 {
			distance += int(xor & 1)
			xor >>= 1
		}
	}

	return distance, nil
}

// BreakRepeatingKeyXor decrypts the input with a repeating-key xor. Returns the decrypted value and the key.
func BreakRepeatingKeyXor(in []byte) ([]byte, []byte, error) {
	ksStart := 2
	ksEnd := 40
	scores := make([]float64, ksEnd-ksStart+1)
	for ks := ksStart; ks < ksEnd+1; ks++ {
		blocks := [][]byte{
			in[0:ks],
			in[ks : 2*ks],
			in[2*ks : 3*ks],
			in[3*ks : 4*ks],
		}

		total := 0
		comparaisons := 0
		for i := range len(blocks) {
			for j := i + 1; j < len(blocks); j++ {
				dist, err := HammingDistance(blocks[i], blocks[j])
				if err != nil {
					return nil, nil, err
				}
				total += dist
				comparaisons++
			}
		}

		avgDist := float64(total) / float64(comparaisons)

		scores[ks-ksStart] = avgDist / float64(ks)
	}

	ks := MinFloat64(scores) + ksStart

	transposed := make([][]byte, ks)
	for chunk := range slices.Chunk(in, ks) {
		for idx, b := range chunk {
			transposed[idx] = append(transposed[idx], b)
		}
	}

	key := make([]byte, ks)
	for i, block := range transposed {
		_, singleKey := DecryptSingleByteXor(block)
		key[i] = singleKey
	}

	encrypted, err := RepeatingKeyXor(in, key)
	if err != nil {
		panic(err)
	}

	return encrypted, key, nil
}

func main() {
	file, err := os.ReadFile("./input.txt")
	if err != nil {
		panic(err)
	}
	file = bytes.TrimRight(file, "\n")

	input, err := base64.StdEncoding.DecodeString(string(file))
	if err != nil {
		panic(err)
	}

	encrypted, key, err := BreakRepeatingKeyXor(input)
	if err != nil {
		panic(err)
	}

	fmt.Println("Key:\n", string(key))
	fmt.Println("Decrypted:\n", string(encrypted))
}
