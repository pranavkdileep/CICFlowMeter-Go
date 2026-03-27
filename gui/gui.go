package gui

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	"client/utils"
)

var preditAttackMu sync.Mutex

func PreditAttack(flow utils.Flow) string {
	preditAttackMu.Lock()
	defer preditAttackMu.Unlock()

	attacks := []string{"Api Error", "Backend Crash"}

	payload := map[string]interface{}{
		" Flow Duration":               flow.FlowDuration,
		" Total Fwd Packets":           flow.TotalfwdPackets,
		" Total Backward Packets":      flow.TotalbwdPackets,
		"Total Length of Fwd Packets":  flow.TotalLengthofFwdPacket,
		" Total Length of Bwd Packets": flow.TotalLengthofBwdPacket,
		" Fwd Packet Length Max":       flow.FwdPacketLengthMax,
		" Fwd Packet Length Min":       flow.FwdPacketLengthMin,
		" Fwd Packet Length Mean":      flow.FwdPacketLengthMean,
		" Fwd Packet Length Std":       flow.FwdPacketLengthStd,
		"Bwd Packet Length Max":        flow.BwdPacketLengthMax,
		" Bwd Packet Length Min":       flow.BwdPacketLengthMin,
		" Bwd Packet Length Mean":      flow.BwdPacketLengthMean,
		" Bwd Packet Length Std":       flow.BwdPacketLengthStd,
		"Flow Bytes/s":                 flow.FlowBytesPerSecond,
		" Flow Packets/s":              flow.FlowPacketsPerSecond,
		" Flow IAT Mean":               flow.FlowIATMean,
		" Flow IAT Std":                flow.FlowIATStd,
		" Flow IAT Max":                flow.FlowIATMax,
		" Flow IAT Min":                flow.FlowIATMin,
		"Fwd IAT Total":                flow.FwdIATTotal,
		" Fwd IAT Mean":                flow.FwdIATMean,
		" Fwd IAT Std":                 flow.FwdIATStd,
		" Fwd IAT Max":                 flow.FwdIATMax,
		" Fwd IAT Min":                 flow.FwdIATMin,
		"Bwd IAT Total":                flow.BwdIATTotal,
		" Bwd IAT Mean":                flow.BwdIATMean,
		" Bwd IAT Std":                 flow.BwdIATStd,
		" Bwd IAT Max":                 flow.BwdIATMax,
		" Bwd IAT Min":                 flow.BwdIATMin,
		"Fwd PSH Flags":                flow.FPSH_cnt,
		" Bwd PSH Flags":               flow.BPSH_cnt,
		" Fwd URG Flags":               flow.FURG_cnt,
		" Bwd URG Flags":               flow.BURG_cnt,
		" Fwd Header Length":           flow.FwdHeaderLength,
		" Bwd Header Length":           flow.BwdHeaderLength,
		"Fwd Packets/s":                flow.FwdPacketsPerSecond,
		" Bwd Packets/s":               flow.BwdPacketsPerSecond,
		" Min Packet Length":           flow.PktLenMin,
		" Max Packet Length":           flow.PktLenMax,
		" Packet Length Mean":          flow.PktLenMean,
		" Packet Length Std":           flow.PktLenStd,
		" Packet Length Variance":      flow.PktLenVar,
		"FIN Flag Count":               flow.FINFlagCount,
		" SYN Flag Count":              flow.SYNFlagCount,
		" RST Flag Count":              flow.RSTFlagCount,
		" PSH Flag Count":              flow.PSHFlagCount,
		" ACK Flag Count":              flow.ACKFlagCount,
		" URG Flag Count":              flow.URGFlagCount,
		" CWE Flag Count":              flow.CWRFlagCount,
		" ECE Flag Count":              flow.ECEFlagCount,
		" Down/Up Ratio":               flow.DownUpRatio,
		" Average Packet Size":         flow.PktLenMean,
		" Avg Fwd Segment Size":        flow.FwdSegSizeAvg,
		" Avg Bwd Segment Size":        flow.BwdSegSizeAvg,
		" Fwd Header Length.1":         flow.FwdHeaderLength,
		"Fwd Avg Bytes/Bulk":           flow.FwdBytesPerBulkAvg,
		" Fwd Avg Packets/Bulk":        flow.FwdPacketsPerBulkAvg,
		" Fwd Avg Bulk Rate":           flow.FwdBulkRateAvg,
		" Bwd Avg Bytes/Bulk":          flow.BwdBytesPerBulkAvg,
		" Bwd Avg Packets/Bulk":        flow.BwdPacketsPerBulkAvg,
		"Bwd Avg Bulk Rate":            flow.BwdBulkRateAvg,
		"Subflow Fwd Packets":          flow.SubflowFwdPkts,
		" Subflow Fwd Bytes":           flow.SubflowFwdBytes,
		" Subflow Bwd Packets":         flow.SubflowBwdPkts,
		" Subflow Bwd Bytes":           flow.SubflowBwdBytes,
		"Init_Win_bytes_forward":       flow.InitWinBytesForward,
		" Init_Win_bytes_backward":     flow.InitWinBytesBackward,
		" act_data_pkt_fwd":            flow.FwdActDataPkts,
		" min_seg_size_forward":        flow.FwdSegSizeMin,
		"Active Mean":                  flow.FlowActive.Mean(),
		" Active Std":                  flow.FlowActive.StandardDeviation(),
		" Active Max":                  flow.FlowActive.Max(),
		" Active Min":                  flow.FlowActive.Min(),
		"Idle Mean":                    flow.FlowIdle.Mean(),
		" Idle Std":                    flow.FlowIdle.StandardDeviation(),
		" Idle Max":                    flow.FlowIdle.Max(),
		" Idle Min":                    flow.FlowIdle.Min(),
	}

	for key, value := range payload {
		payload[key] = sanitizeJSONValue(value)
	}

	b, err := json.Marshal(payload)
	if err != nil {
		// Append error to error.txt
		f, ferr := os.OpenFile("error.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if ferr == nil {
			defer f.Close()
			f.WriteString(time.Now().Format(time.RFC3339) + ": json.Marshal error: " + err.Error() + "\n")
		}
		return "b error"
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post("http://localhost:5000/predict", "application/json", bytes.NewReader(b))
	if err != nil {
		return attacks[rand.Intn(len(attacks))]
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return attacks[rand.Intn(len(attacks))]
	}

	var out struct {
		PredictedLabel string    `json:"predicted_label"`
		ClassIndex     int       `json:"class_index"`
		Probabilities  []float64 `json:"probabilities"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		//return attacks[rand.Intn(len(attacks))]
		return attacks[rand.Intn(len(attacks))]
	}
	if out.PredictedLabel != "" {
		return out.PredictedLabel
	}
	return attacks[rand.Intn(len(attacks))]
}

func GenerateIncidentID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func sanitizeJSONValue(value interface{}) interface{} {
	switch v := value.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0.0
		}
	case float32:
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			return float32(0)
		}
	}

	return value
}
