package utils

import (
	"log"
	"net/http"
)

func ParseClientIP(r *http.Request) string {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.Header.Get("X-Nf-Client-Connection-Ip") // Netlify specific header
	}
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}

	// In case of multiple IPs (comma separated), take the first one
	if len(ipAddress) > 0 {
		log.Printf("Parsing client IP address string: %s", ipAddress)
		for i := 0; i < len(ipAddress); i++ {
			if ipAddress[i] == ',' || ipAddress[i] == ' ' {
				return ipAddress[:i]
			}
		}
	}

	return ipAddress
}
