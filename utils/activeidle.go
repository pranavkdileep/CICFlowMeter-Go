package utils

// CICFlowMeter-like Active/Idle segmentation.
//
// This mirrors the Java logic in BasicFlow.updateActiveIdleTime(currentTime, threshold):
// - If the gap since the last active packet exceeds threshold, the previous active period
//   (endActiveTime-startActiveTime) is added to FlowActive.
// - The idle period (currentTime-endActiveTime) is added to FlowIdle.
// - Then a new active period starts at currentTime.
//
// Units: microseconds (same as other timing features in this repo).

func UpdateActiveIdleTime(flow *Flow, currentTimeMicros int64, thresholdMicros int64) {
	if flow == nil {
		return
	}

	// Initialize on first observation.
	if flow.StartActiveTimeMicros == 0 && flow.EndActiveTimeMicros == 0 {
		flow.StartActiveTimeMicros = currentTimeMicros
		flow.EndActiveTimeMicros = currentTimeMicros
		return
	}

	gap := currentTimeMicros - flow.EndActiveTimeMicros
	if gap < 0 {
		// Out-of-order timestamp; keep state consistent and avoid negative durations.
		flow.EndActiveTimeMicros = currentTimeMicros
		return
	}

	if thresholdMicros > 0 && gap > thresholdMicros {
		active := flow.EndActiveTimeMicros - flow.StartActiveTimeMicros
		if active > 0 {
			flow.FlowActive.AddValue(float64(active))
		}

		idle := currentTimeMicros - flow.EndActiveTimeMicros
		if idle > 0 {
			flow.FlowIdle.AddValue(float64(idle))
		}

		flow.StartActiveTimeMicros = currentTimeMicros
		flow.EndActiveTimeMicros = currentTimeMicros
		return
	}

	flow.EndActiveTimeMicros = currentTimeMicros
}

// EndActiveIdleTime finalizes the current active segment.
// Mirrors the Java BasicFlow.endActiveIdleTime(...) behavior of pushing the last
// active duration into FlowActive (if > 0).
func EndActiveIdleTime(flow *Flow) {
	if flow == nil {
		return
	}
	active := flow.EndActiveTimeMicros - flow.StartActiveTimeMicros
	if active > 0 {
		flow.FlowActive.AddValue(float64(active))
	}
}
