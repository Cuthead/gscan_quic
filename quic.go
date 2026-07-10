package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var errNoSuchBucket = []byte("<?xml version='1.0' encoding='UTF-8'?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>")

func testQuic(ctx context.Context, ip string, config *ScanConfig, record *ScanRecord) bool {

	var VerifyCN = config.VerifyCommonName
	var Code = config.ValidStatusCode
	start := time.Now()

	quicCfg := &quic.Config{
		HandshakeIdleTimeout: config.HandshakeTimeout,
		KeepAlivePeriod:      0,
	}

	serverName := ""
	if len(config.ServerName) == 0 {
		serverName = randomHost()
	} else {
		serverName = randomChoice(config.ServerName)
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		NextProtos:         []string{"h3-29", "h3", "hq", "quic"},
	}

	ctx, cancel := context.WithTimeout(ctx, config.ScanMaxRTT)
	defer cancel()

	quicConn, err := quic.DialAddrEarly(ctx, net.JoinHostPort(ip, "443"), tlsCfg, quicCfg)
	if err != nil {
		logFail(4, ip, "dial", fmt.Sprintf("sni=%s error=%s", serverName, err.Error()))
		return false
	}
	defer func() {
		err := quicConn.CloseWithError(0, "")
		if err != nil {
			fmt.Println("Error closing QUIC session:", err)
		}
	}()

	// lv1 只会验证证书是否存在
	cs := quicConn.ConnectionState().TLS
	if !cs.HandshakeComplete || len(cs.PeerCertificates) == 0 {
		logFail(4, ip, "handshake", fmt.Sprintf("sni=%s error=no peer certificates", serverName))
		return false
	}

	// lv2 验证证书是否正确
	pcs := cs.PeerCertificates
	if config.Level > 1 {
		CN := pcs[0].DNSNames[0]
		if CN != VerifyCN {
			logFail(3, ip, "cn", fmt.Sprintf("sni=%s want_cn=%s got_cn=%s", serverName, VerifyCN, CN))
			return false
		}
	}

	// lv3 使用 http 访问来验证
	if config.Level > 2 {
		tr := &http3.RoundTripper{DisableCompression: true}
		defer func() {
			err := tr.Close()
			if err != nil {
				fmt.Println("Error closing HTTP/3 transport:", err)
			}
		}()
		tr.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			return quicConn, err
		}
		// 设置超时
		hclient := &http.Client{
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: config.ScanMaxRTT - time.Since(start),
		}
		host := config.HTTPVerifyHosts[rand.Intn(len(config.HTTPVerifyHosts))]
		url := "https://" + host
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Close = true
		resp, _ := hclient.Do(req)
		if resp == nil || resp.StatusCode != Code {
			detail := fmt.Sprintf("sni=%s host=%s error=no response", serverName, host)
			if resp != nil {
				detail = fmt.Sprintf("sni=%s host=%s got_code=%d", serverName, host, resp.StatusCode)
			}
			logFail(2, ip, "status", detail)
			return false
		}
		if resp.Body != nil {
			defer func() {
				err := resp.Body.Close()
				if err != nil {
					fmt.Println("Error closing response body:", err)
				}
			}()
			// lv4 验证是否是 NoSuchBucket 错误
			if config.Level > 3 && resp.Header.Get("Content-Type") == "application/xml; charset=UTF-8" { // 也许条件改为 || 更好
				body, err := io.ReadAll(resp.Body)
				if err != nil || bytes.Equal(body, errNoSuchBucket) {
					logFail(2, ip, "status", fmt.Sprintf("sni=%s host=%s error=NoSuchBucket body", serverName, host))
					return false
				}
			} else {
				io.Copy(io.Discard, resp.Body)
			}
		}
	}

	if rtt := time.Since(start); rtt > config.ScanMinRTT && rtt <= config.ScanMaxRTT {
		record.RTT += rtt
		return true
	}
	return false
}
