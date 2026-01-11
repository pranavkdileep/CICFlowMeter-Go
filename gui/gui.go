package gui

import (
	"client/utils"
	"math/rand"
	"time"
)



func PreditAttack(flow utils.Flow) string {
	delay := time.Millisecond * time.Duration(rand.Intn(500)+100)
	time.Sleep(delay)
	attacks := []string{"BENIGN", "DrDoS_DNS", "DrDoS_LDAP", "DrDoS_MSSQL", "DrDoS_NTP", "DrDoS_NetBIOS", "DrDoS_SNMP", "DrDoS_SSDP", "DrDoS_UDP", "Syn", "TFTP", "UDP-lag", "WebDDoS"}
	return attacks[rand.Intn(len(attacks))]
}