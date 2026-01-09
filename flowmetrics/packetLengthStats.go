package flowmetrics

import "math"

// Stats matches CICFlowMeter's use of Apache Commons SummaryStatistics enough for
// Min/Max/Mean/Std over per-packet payload bytes.
type Stats struct {
	n    int64
	sum  float64
	sum2 float64
	min  float64
	max  float64
}

func NewStats() Stats {
	return Stats{
		min: math.Inf(1),
		max: math.Inf(-1),
	}
}

func (s *Stats) AddValue(v float64) {
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

func (s Stats) N() int64 { return s.n }

func (s Stats) Min() float64 {
	if s.n == 0 {
		return 0
	}
	return s.min
}

func (s Stats) Max() float64 {
	if s.n == 0 {
		return 0
	}
	return s.max
}

func (s Stats) Mean() float64 {
	if s.n == 0 {
		return 0
	}
	return s.sum / float64(s.n)
}

// StandardDeviation returns the sample standard deviation (N-1 in the denominator),
// which matches Apache Commons Math SummaryStatistics.getStandardDeviation().
func (s Stats) StandardDeviation() float64 {
	if s.n <= 1 {
		return 0
	}
	n := float64(s.n)
	// sample variance = (sum2 - sum^2/n) / (n-1)
	variance := (s.sum2 - (s.sum*s.sum)/n) / (n - 1.0)
	if variance < 0 {
		// guard against tiny negative due to floating-point error
		variance = 0
	}
	return math.Sqrt(variance)
}

// Variance returns the sample variance (N-1 in the denominator), matching
// Apache Commons Math SummaryStatistics.getVariance().
func (s Stats) Variance() float64 {
	if s.n <= 1 {
		return 0
	}
	n := float64(s.n)
	variance := (s.sum2 - (s.sum*s.sum)/n) / (n - 1.0)
	if variance < 0 {
		variance = 0
	}
	return variance
}

// --- CICFlowMeter-like getters for fwd/bwd packet length stats ---

func FwdPacketLengthMin(fwd Stats) float64 {
	if fwd.N() > 0 {
		return fwd.Min()
	}
	return 0
}

func FwdPacketLengthMax(fwd Stats) float64 {
	if fwd.N() > 0 {
		return fwd.Max()
	}
	return 0
}

func FwdPacketLengthMean(fwd Stats) float64 {
	if fwd.N() > 0 {
		return fwd.Mean()
	}
	return 0
}

func FwdPacketLengthStd(fwd Stats) float64 {
	if fwd.N() > 0 {
		return fwd.StandardDeviation()
	}
	return 0
}

func BwdPacketLengthMin(bwd Stats) float64 {
	if bwd.N() > 0 {
		return bwd.Min()
	}
	return 0
}

func BwdPacketLengthMax(bwd Stats) float64 {
	// This matches the Java snippet:
	// return (bwdPktStats.getN() > 0L)? bwdPktStats.getMax():0;
	if bwd.N() > 0 {
		return bwd.Max()
	}
	return 0
}

func BwdPacketLengthMean(bwd Stats) float64 {
	if bwd.N() > 0 {
		return bwd.Mean()
	}
	return 0
}

func BwdPacketLengthStd(bwd Stats) float64 {
	if bwd.N() > 0 {
		return bwd.StandardDeviation()
	}
	return 0
}
