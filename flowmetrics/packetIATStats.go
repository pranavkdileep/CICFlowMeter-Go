package flowmetrics

import (
	"math"
)

type IATStats struct {
	n    int64
	sum  float64
	sum2 float64
	min  float64
	max  float64
}

func NewIATStats() IATStats {
	return IATStats{
		min: math.Inf(1),
		max: math.Inf(-1),
	}
}

func (s *IATStats) AddValue(v float64) {
	s.n++
	s.sum += v
	s.sum2 += v * v
	if v < s.min {
		s.min = v
	}
	if v > s.max {
		s.max = v
	}
}

func (s IATStats) N() int64 { return s.n }
func (s IATStats) Sum() float64 {
	if s.n == 0 {
		return 0
	}
	return s.sum
}
func (s IATStats) Min() float64 {
	if s.n == 0 {
		return 0
	}
	return s.min
}
func (s IATStats) Max() float64 {
	if s.n == 0 {
		return 0
	}
	return s.max
}
func (s IATStats) Mean() float64 {
	if s.n == 0 {
		return 0
	}
	return s.sum / float64(s.n)
}

func (s IATStats) StandardDeviation() float64 {
	if s.n <= 1 {
		return 0
	}
	n := float64(s.n)
	variance := (s.sum2 - (s.sum*s.sum)/n) / (n - 1.0)
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)
}

func FlowIATMean(totalPackets int, flowIAT IATStats) float64 {
	if totalPackets <= 1 { return 0 }
	return flowIAT.Mean()
}

func FlowIATStd(totalPackets int, flowIAT IATStats) float64 {
	if totalPackets <= 1 { return 0 }
	return flowIAT.StandardDeviation()
}

func FlowIATMax(totalPackets int, flowIAT IATStats) float64 {
	if totalPackets <= 1 { return 0 }
	return flowIAT.Max()
}

func FlowIATMin(totalPackets int, flowIAT IATStats) float64 {
	if totalPackets <= 1 { return 0 }
	return flowIAT.Min()
}

func FwdIATTotal(fwdPktCount int, fwdIAT IATStats) float64 {
	if fwdPktCount <= 1 {
		return 0
	}
	return fwdIAT.Sum()
}

func FwdIATMean(fwdPktCount int, fwdIAT IATStats) float64 {
	if fwdPktCount <= 1 {
		return 0
	}
	return fwdIAT.Mean()
}

func FwdIATStd(fwdPktCount int, fwdIAT IATStats) float64 {
	if fwdPktCount <= 1 {
		return 0
	}
	return fwdIAT.StandardDeviation()
}

func FwdIATMax(fwdPktCount int, fwdIAT IATStats) float64 {
	if fwdPktCount <= 1 {
		return 0
	}
	return fwdIAT.Max()
}

func FwdIATMin(fwdPktCount int, fwdIAT IATStats) float64 {
	if fwdPktCount <= 1 {
		return 0
	}
	return fwdIAT.Min()
}

func BwdIATTotal(bwdPktCount int, bwdIAT IATStats) float64 {
	if bwdPktCount <= 1 {
		return 0
	}
	return bwdIAT.Sum()
}

func BwdIATMean(bwdPktCount int, bwdIAT IATStats) float64 {
	if bwdPktCount <= 1 {
		return 0
	}
	return bwdIAT.Mean()
}

func BwdIATStd(bwdPktCount int, bwdIAT IATStats) float64 {
	if bwdPktCount <= 1 {
		return 0
	}
	return bwdIAT.StandardDeviation()
}

func BwdIATMax(bwdPktCount int, bwdIAT IATStats) float64 {
	if bwdPktCount <= 1 {
		return 0
	}
	return bwdIAT.Max()
}

func BwdIATMin(bwdPktCount int, bwdIAT IATStats) float64 {
	if bwdPktCount <= 1 {
		return 0
	}
	return bwdIAT.Min()
}