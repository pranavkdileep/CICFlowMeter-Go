package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
)

func InitCSVFile(filename string, headers []string) *csv.Writer {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create CSV file: %v", err)
	}

	writer := csv.NewWriter(file)

	// Write headers
	if err := writer.Write(headers); err != nil {
		log.Fatalf("Failed to write headers to CSV file: %v", err)
	}
	writer.Flush()

	return writer
}

func AppendToCSV(writer *csv.Writer, record []string) {
	if err := writer.Write(record); err != nil {
		log.Fatalf("Failed to write record to CSV file: %v", err)
	}
	writer.Flush()
}

func CloseCSVFile(writer *csv.Writer) {
	writer.Flush()
	if err := writer.Error(); err != nil {
		log.Fatalf("Error flushing CSV writer: %v", err)
	}
}

func ReadCSVFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Failed to read record from CSV file: %v", err)
		}
		fmt.Println(record)
	}
}