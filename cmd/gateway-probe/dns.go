// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	qtypeA     uint16 = 1
	qtypeNS    uint16 = 2
	qtypeCNAME uint16 = 5
	qtypeMX    uint16 = 15
	qtypeTXT   uint16 = 16
	qtypeAAAA  uint16 = 28
	qtypeSRV   uint16 = 33
	qtypeSVCB  uint16 = 64
	qtypeHTTPS uint16 = 65

	qclassIN uint16 = 1

	rcodeNoError = 0
	rcodeRefused = 5
)

type dnsReply struct {
	Rcode   int
	ANCount int
	Addrs   []netip.Addr
}

func rcodeName(rcode int) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

func buildDNSQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	trimmed := strings.TrimSuffix(strings.TrimSpace(name), ".")
	if trimmed == "" {
		return nil, errors.New("empty DNS query name")
	}
	labels := strings.Split(trimmed, ".")
	buf := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // standard query, RD=1
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT=1

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label %q", label)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0) // root terminator
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], qclassIN)
	buf = append(buf, tail[:]...)
	return buf, nil
}

func parseDNSReply(pkt []byte, wantID uint16) (dnsReply, error) {
	if len(pkt) < 12 {
		return dnsReply{}, fmt.Errorf("short DNS packet (%d bytes)", len(pkt))
	}
	gotID := binary.BigEndian.Uint16(pkt[0:2])
	if gotID != wantID {
		return dnsReply{}, fmt.Errorf("DNS txid mismatch: got %d want %d", gotID, wantID)
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 == 0 {
		return dnsReply{}, errors.New("DNS packet is not a response (QR=0)")
	}
	qdCount := int(binary.BigEndian.Uint16(pkt[4:6]))
	anCount := int(binary.BigEndian.Uint16(pkt[6:8]))
	reply := dnsReply{
		Rcode:   int(flags & 0x000f),
		ANCount: anCount,
	}

	off := 12
	for i := 0; i < qdCount; i++ {
		next, err := skipDNSName(pkt, off)
		if err != nil {
			return dnsReply{}, fmt.Errorf("skip question name: %w", err)
		}
		if next+4 > len(pkt) {
			return dnsReply{}, errors.New("truncated DNS question")
		}
		off = next + 4
	}

	for i := 0; i < anCount; i++ {
		next, err := skipDNSName(pkt, off)
		if err != nil {
			return dnsReply{}, fmt.Errorf("skip answer name: %w", err)
		}
		if next+10 > len(pkt) {
			return dnsReply{}, errors.New("truncated DNS answer header")
		}
		rrType := binary.BigEndian.Uint16(pkt[next : next+2])
		rdLen := int(binary.BigEndian.Uint16(pkt[next+8 : next+10]))
		rdataStart := next + 10
		rdataEnd := rdataStart + rdLen
		if rdataEnd > len(pkt) {
			return dnsReply{}, errors.New("truncated DNS answer rdata")
		}
		if rrType == qtypeA && rdLen == 4 {
			var b [4]byte
			copy(b[:], pkt[rdataStart:rdataEnd])
			reply.Addrs = append(reply.Addrs, netip.AddrFrom4(b))
		}
		off = rdataEnd
	}
	return reply, nil
}

func skipDNSName(pkt []byte, off int) (int, error) {
	if off < 0 || off >= len(pkt) {
		return 0, errors.New("offset out of bounds")
	}
	for jumps := 0; jumps < 128; jumps++ {
		if off >= len(pkt) {
			return 0, errors.New("unterminated DNS name")
		}
		length := int(pkt[off])
		if length == 0 {
			return off + 1, nil
		}
		if length&0xc0 == 0xc0 {
			if off+1 >= len(pkt) {
				return 0, errors.New("truncated DNS pointer")
			}
			return off + 2, nil
		}
		if length&0xc0 != 0 {
			return 0, fmt.Errorf("invalid DNS label prefix 0x%x", length)
		}
		off += 1 + length
	}
	return 0, errors.New("DNS name too long")
}

func queryDNS(ctx context.Context, proto, server, qname string, qtype uint16, localAddr *net.UDPAddr, timeout time.Duration) (dnsReply, error) {
	const txID uint16 = 0x4242
	wire, err := buildDNSQuery(txID, qname, qtype)
	if err != nil {
		return dnsReply{}, err
	}
	if proto == "tcp" {
		return queryDNSTCP(ctx, server, wire, txID, timeout)
	}
	return queryDNSUDP(ctx, server, wire, txID, localAddr, timeout)
}

func queryDNSUDP(ctx context.Context, server string, wire []byte, txID uint16, localAddr *net.UDPAddr, timeout time.Duration) (dnsReply, error) {
	d := net.Dialer{
		Timeout: timeout,
		Control: reuseAddrControl,
	}
	if localAddr != nil {
		d.LocalAddr = localAddr
	}
	conn, err := d.DialContext(ctx, "udp4", server)
	if err != nil {
		return dnsReply{}, err
	}
	defer closeQuietly(conn)

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return dnsReply{}, err
	}
	if _, err := conn.Write(wire); err != nil {
		return dnsReply{}, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return dnsReply{}, err
	}
	return parseDNSReply(buf[:n], txID)
}

func queryDNSTCP(ctx context.Context, server string, wire []byte, txID uint16, timeout time.Duration) (dnsReply, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp4", server)
	if err != nil {
		return dnsReply{}, err
	}
	defer closeQuietly(conn)

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return dnsReply{}, err
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return dnsReply{}, err
	}
	if _, err := conn.Write(wire); err != nil {
		return dnsReply{}, err
	}
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return dnsReply{}, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen == 0 || respLen > 65535 {
		return dnsReply{}, fmt.Errorf("invalid TCP DNS length %d", respLen)
	}
	buf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return dnsReply{}, err
	}
	return parseDNSReply(buf, txID)
}
