package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"
)

func testSni(ctx context.Context, ip string, config *ScanConfig, record *ScanRecord) bool {
	tlscfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	var Host string
	var VerifyCN string
	var Path string
	var Code int
	var Method string
	if len(config.HTTPVerifyHosts) == 0 {
		Host = randomHost()
	} else {
		Host = config.HTTPVerifyHosts[rand.Intn(len(config.HTTPVerifyHosts))]
	}
	VerifyCN = config.VerifyCommonName
	Code = config.ValidStatusCode
	Path = config.HTTPPath
	Method = config.HTTPMethod

	for _, serverName := range config.ServerName {
		start := time.Now()

		ctx, cancel := context.WithTimeout(ctx, config.ScanMaxRTT)
		defer cancel()

		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
		if err != nil {
			logFail(4, ip, "dial", fmt.Sprintf("sni=%s error=%s", serverName, err.Error()))
			return false
		}

		tlscfg.ServerName = serverName
		tlsconn := tls.Client(conn, tlscfg)
		tlsconn.SetDeadline(time.Now().Add(config.HandshakeTimeout))
		if err = tlsconn.Handshake(); err != nil {
			logFail(4, ip, "handshake", fmt.Sprintf("sni=%s error=%s", serverName, err.Error()))
			tlsconn.Close()
			return false
		}
		if config.Level > 1 {
			pcs := tlsconn.ConnectionState().PeerCertificates
			gotCN := ""
			if len(pcs) > 0 {
				gotCN = pcs[0].Subject.CommonName
			}
			if len(pcs) == 0 || gotCN != VerifyCN {
				logFail(3, ip, "cn", fmt.Sprintf("sni=%s want_cn=%s got_cn=%s", serverName, VerifyCN, gotCN))
				tlsconn.Close()
				return false
			}
		}
		if config.Level > 2 {
			req, err := http.NewRequest(Method, "https://"+net.JoinHostPort(ip, "443")+Path, nil)
			req.Host = Host
			if err != nil {
				logFail(2, ip, "http", fmt.Sprintf("sni=%s host=%s method=%s path=%s error=build request: %s", serverName, Host, Method, Path, err.Error()))
				tlsconn.Close()
				return false
			}
			httpconn := &http.Client{
				Transport: &http.Transport{
					DialTLS: func(network, addr string) (net.Conn, error) { return tlsconn, nil },
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Timeout: config.ScanMaxRTT - time.Since(start),
			}
			tlsconn.SetDeadline(time.Now().Add(config.ScanMaxRTT - time.Since(start)))
			resp, err := httpconn.Do(req)
			if err != nil {
				logFail(2, ip, "http", fmt.Sprintf("sni=%s host=%s method=%s path=%s error=%s", serverName, Host, Method, Path, err.Error()))
				tlsconn.Close()
				return false
			}
			// io.Copy(os.Stdout, resp.Body)
			// if resp.Body != nil {
			// 	io.Copy(io.Discard, resp.Body)
			// 	resp.Body.Close()
			// }
			if resp.StatusCode != Code {
				logFail(2, ip, "status", fmt.Sprintf("sni=%s host=%s method=%s path=%s want_code=%d got_code=%d", serverName, Host, Method, Path, Code, resp.StatusCode))
				tlsconn.Close()
				return false
			}
		}

		tlsconn.Close()

		rtt := time.Since(start)
		if rtt < config.ScanMinRTT || rtt > config.ScanMaxRTT {
			return false
		}
		record.RTT += rtt
	}
	return true
}
