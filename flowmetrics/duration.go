package flowmetrics

import (
	"time"
)

func CalculateFlowDuration(startTime, endTime time.Time) int64 {
	if startTime.IsZero() || endTime.IsZero() {
		return 0
	}
	
	return endTime.Sub(startTime).Microseconds()
}