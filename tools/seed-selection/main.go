package main

import (
	"bufio"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: go run main.go <filename>")
		return
	}

	result, err := parseHexFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Read %d programs\n", len(result))

	fmt.Printf("\n>>>>>>>>> Base Statistics <<<<<<<<<< \n")
	measureDistribution(allOnce(result))

	const runs = 300000

	fmt.Printf("\n>>>>>>>>> Weighted by Total PCs <<<<<<<<<< \n")
	measureDistribution(baseAlgorithm(result, runs))

	fmt.Printf("\n>>>>>>>>> Random PC, then random Program <<<<<<<<<< \n")
	measureDistribution(selectByPC(result, runs))

	fmt.Printf("\n>>>>>>>>> Weighted Random PC, then random Program <<<<<<<<<< \n")
	measureDistribution(selectByPCWeighted(result, runs))

	//	fmt.Printf("\n>>>>>>>>> Dynamic Saturation (sample of 200) <<<<<<<<<< \n")
	//	measureDistribution(dynamicSaturation(result, 200000, 200))

	fmt.Printf("\n>>>>>>>>> Foster Median (sample of 300) <<<<<<<<<< \n")
	measureDistribution(dynamicBelowMedian(result, runs, 300))
}

func allOnce(progs [][]uint64) map[uint64]int64 {
	ret := map[uint64]int64{}
	for _, prog := range progs {
		for _, pc := range prog {
			ret[pc]++
		}
	}
	return ret
}

type ProgramsList struct {
	progs    [][]uint64
	sumPrios int64
	accPrios []int64
}

func (pl *ProgramsList) chooseProgram(r *rand.Rand) []uint64 {
	if len(pl.progs) == 0 {
		return nil
	}
	randVal := r.Int63n(pl.sumPrios + 1)
	idx := sort.Search(len(pl.accPrios), func(i int) bool {
		return pl.accPrios[i] >= randVal
	})
	if idx == len(pl.progs) {
		idx--
	}
	return pl.progs[idx]
}

func (pl *ProgramsList) saveProgram(p []uint64) {
	prio := int64(len(p))
	if prio == 0 {
		prio = 1
	}
	pl.sumPrios += prio
	pl.accPrios = append(pl.accPrios, pl.sumPrios)
	pl.progs = append(pl.progs, p)
}

func baseAlgorithm(programs [][]uint64, n int) map[uint64]int64 {
	pl := &ProgramsList{}
	for _, p := range programs {
		pl.saveProgram(p)
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	distribution := make(map[uint64]int64)

	for i := 0; i < n; i++ {
		prog := pl.chooseProgram(r)
		for _, pc := range prog {
			distribution[pc]++
		}
	}
	return distribution
}

func selectByPC(programs [][]uint64, n int) map[uint64]int64 {
	pcToProgs := make(map[uint64][][]uint64)
	var allPCs []uint64

	for _, prog := range programs {
		for _, pc := range prog {
			if _, exists := pcToProgs[pc]; !exists {
				allPCs = append(allPCs, pc)
			}
			pcToProgs[pc] = append(pcToProgs[pc], prog)
		}
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	distribution := make(map[uint64]int64)

	for i := 0; i < n; i++ {
		randomPC := allPCs[r.Intn(len(allPCs))]
		candidates := pcToProgs[randomPC]
		selectedProg := candidates[r.Intn(len(candidates))]

		for _, pc := range selectedProg {
			distribution[pc]++
		}
	}
	return distribution
}

func selectByPCWeighted(programs [][]uint64, n int) map[uint64]int64 {
	pcToProgs := make(map[uint64][][]uint64)
	for _, prog := range programs {
		for _, pc := range prog {
			pcToProgs[pc] = append(pcToProgs[pc], prog)
		}
	}

	pcs := make([]uint64, 0, len(pcToProgs))
	accWeights := make([]float64, 0, len(pcToProgs))
	var currentSum float64

	for pc, progs := range pcToProgs {
		pcs = append(pcs, pc)
		currentSum += 1.0 / float64(len(progs))
		accWeights = append(accWeights, currentSum)
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	dist := make(map[uint64]int64)

	for i := 0; i < n; i++ {
		target := r.Float64() * currentSum
		idx := sort.Search(len(accWeights), func(j int) bool {
			return accWeights[j] >= target
		})
		if idx == len(pcs) {
			idx--
		}
		candidates := pcToProgs[pcs[idx]]
		for _, pc := range candidates[r.Intn(len(candidates))] {
			dist[pc]++
		}
	}
	return dist
}

func dynamicBelowMedian(programs [][]uint64, n, sampleSize int) map[uint64]int64 {
	dist := make(map[uint64]int64)

	const recalcMedianIn = 1000
	median := int64(recalcMedianIn)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < n; i++ {
		if i%25000 == 0 {
			fmt.Printf("%d..", i)
		}
		if i > 0 && i%recalcMedianIn == 0 {
			var counts []int
			for _, cnt := range dist {
				counts = append(counts, int(cnt))
			}
			sort.Ints(counts)
			median = int64(counts[len(counts)/2])
		}
		var bestProg []uint64
		maxScore := 0
		for j := 0; j < sampleSize; j++ {
			cand := programs[r.Intn(len(programs))]
			var sum int
			for _, pc := range cand {
				if dist[pc] < median {
					sum++
				}
			}
			if sum >= maxScore {
				maxScore = sum
				bestProg = cand
			}
		}
		for _, pc := range bestProg {
			dist[pc]++
		}
	}
	fmt.Printf("\n")
	return dist
}

func dynamicSaturation(programs [][]uint64, n, sampleSize int) map[uint64]int64 {
	dist := make(map[uint64]int64)
	for _, p := range programs {
		for _, pc := range p {
			dist[pc] = 0
		}
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < n; i++ {
		if i%25000 == 0 {
			fmt.Printf("%d..", i)
		}
		var bestProg []uint64
		maxScore := -1.0

		for j := 0; j < sampleSize; j++ {
			cand := programs[r.Intn(len(programs))]
			score := 0.0
			for _, pc := range cand {
				score += 1.0 / float64(dist[pc]+1)
			}
			if score > maxScore {
				maxScore = score
				bestProg = cand
			}
		}
		for _, pc := range bestProg {
			dist[pc]++
		}
	}
	fmt.Printf("\n")
	return dist
}

func measureDistribution(dist map[uint64]int64) {
	if len(dist) == 0 {
		fmt.Println("No data to measure.")
		return
	}

	counts := make([]int, 0, len(dist))
	var totalHits uint64
	var minVal, maxVal int64
	first := true

	nonZero := 0
	for _, count := range dist {
		counts = append(counts, int(count))
		totalHits += uint64(count)
		if first {
			minVal, maxVal = count, count
			first = false
		}
		minVal = min(minVal, count)
		maxVal = max(maxVal, count)
		if count > 0 {
			nonZero++
		}
	}

	sort.Ints(counts)
	n := float64(len(dist))

	getPercentile := func(p float64) int {
		idx := max(0, int(math.Ceil(p/100.0*n))-1)
		return counts[idx]
	}

	fmt.Printf("\n--- Hit Count Percentiles ---\n")
	fmt.Printf("P10: %d\n", getPercentile(10))
	fmt.Printf("P50: %d (Median)\n", getPercentile(50))
	fmt.Printf("P75: %d\n", getPercentile(75))
	fmt.Printf("P90: %d\n", getPercentile(90))
	fmt.Printf("P95: %d\n", getPercentile(95))
	fmt.Printf("P99: %d\n", getPercentile(99))
	fmt.Printf("Max: %d\n", counts[len(counts)-1])

	var currAcc int
	for i := len(counts) - 1; i >= 0; i-- {
		currAcc += counts[i]
		if uint64(currAcc) > totalHits/2 {
			fmt.Printf("top %d PCs got >50%% of all executions\n", len(counts)-i)
			break
		}
	}

	mean := float64(totalHits) / n
	var sumSqDiff, entropy float64
	for _, count := range dist {
		diff := float64(count) - mean
		sumSqDiff += diff * diff
		if p := float64(count) / float64(totalHits); p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	stdDev := math.Sqrt(sumSqDiff / n)
	fmt.Printf("\n--- Distribution Metrics ---\n")
	fmt.Printf("Unique PCs Explored: %d\n", nonZero)
	fmt.Printf("Mean Hits per PC: %.2f\n", mean)
	fmt.Printf("Range (Min/Max): %d / %d\n", minVal, maxVal)
	fmt.Printf("Std Deviation: %.2f\n", stdDev)
	fmt.Printf("Coeff of Variation: %.2f%% (Lower is more even)\n", (stdDev/mean)*100)
	fmt.Printf("Shannon Entropy: %.4f bits (Max possible: %.4f)\n", entropy, math.Log2(n))
}

func parseHexFile(filename string) ([][]uint64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data [][]uint64
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		row := make([]uint64, 0, len(fields))
		for _, field := range fields {
			val, err := strconv.ParseUint(strings.TrimPrefix(field, "0x"), 16, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse hex %q: %w", field, err)
			}
			row = append(row, val)
		}
		data = append(data, row)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return data, nil
}
