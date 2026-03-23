package textutil

import "math"

func ShannonEntropy(input string) float64 {
	if input == "" {
		return 0
	}
	freq := make(map[rune]float64, len(input))
	for _, r := range input {
		freq[r]++
	}
	var entropy float64
	size := float64(len([]rune(input)))
	for _, count := range freq {
		p := count / size
		entropy -= p * math.Log2(p)
	}
	return entropy
}
