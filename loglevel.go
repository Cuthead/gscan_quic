package main

import "log"

// LogLevel controls how much failure detail gets logged, independent of
// ScanConfig.Level (which controls how many verification stages actually
// run). Successful hits are always logged via ScanRecords.AddRecord
// regardless of LogLevel. Higher levels add progressively more common (and
// therefore noisier) failure categories:
//
//	1 - hits only (default)
//	2 - + HTTP status-code failures
//	3 - + certificate / CommonName verification failures
//	4 - + TLS connect / handshake failures
//	5 - + ping failures
var LogLevel = 1

// logFail logs a failed test attempt for ip, tagged with reason, if LogLevel
// is at least minLevel. detail is optional extra context (an error message,
// a mismatched value, etc.) and may be empty.
func logFail(minLevel int, ip, reason, detail string) {
	if LogLevel < minLevel {
		return
	}
	if detail == "" {
		log.Printf("Tested IP=%s RESULT=fail REASON=%s\n", ip, reason)
		return
	}
	log.Printf("Tested IP=%s RESULT=fail REASON=%s DETAIL=%s\n", ip, reason, detail)
}
