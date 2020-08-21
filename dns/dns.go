package dns

import (
	"errors"
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	errLameReferral                = errors.New("lame referral")
	errCannotUnmarshalDNSMessage   = errors.New("cannot unmarshal DNS message")
	errCannotMarshalDNSMessage     = errors.New("cannot marshal DNS message")
	errServerMisbehaving           = errors.New("server misbehaving")
	errInvalidDNSResponse          = errors.New("invalid DNS response")
	errNoAnswerFromDNSServer       = errors.New("no answer from DNS server")
	errServerTemporarlyMisbehaving = errors.New("server misbehaving")
	errNoSuchHost                  = errors.New("No Such Host")
)

func newRequest(q dnsmessage.Question) (id uint16, udpReq, tcpReq []byte, err error) {
	id = uint16(rand.Int()) ^ uint16(time.Now().UnixNano())
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return 0, nil, nil, err
	}
	if err := b.Question(q); err != nil {
		return 0, nil, nil, err
	}
	tcpReq, err = b.Finish()
	udpReq = tcpReq[2:]
	l := len(tcpReq) - 2
	tcpReq[0] = byte(l >> 8)
	tcpReq[1] = byte(l)
	return id, udpReq, tcpReq, err
}

func dnsPacketRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 512) // see RFC 1035
	for {
		n, err := c.Read(b)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		var p dnsmessage.Parser
		// Ignore invalid responses as they may be malicious
		// forgery attempts. Instead continue waiting until
		// timeout. See golang.org/issue/13281.
		h, err := p.Start(b[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil || !checkResponse(id, query, h, q) {
			continue
		}
		return p, h, nil
	}
}

func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response {
		return false
	}
	if reqID != respHdr.ID {
		return false
	}
	if reqQues.Type != respQues.Type || reqQues.Class != respQues.Class || !equalASCIIName(reqQues.Name, respQues.Name) {
		return false
	}
	return true
}

func equalASCIIName(x, y dnsmessage.Name) bool {
	if x.Length != y.Length {
		return false
	}
	for i := 0; i < int(x.Length); i++ {
		a := x.Data[i]
		b := y.Data[i]
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	if h.RCode == dnsmessage.RCodeNameError {
		return errNoSuchHost
	}

	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return errCannotUnmarshalDNSMessage
	}

	// libresolv continues to the next server when it receives
	// an invalid referral response. See golang.org/issue/15434.
	if h.RCode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone {
		return errLameReferral
	}

	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		// None of the error codes make sense
		// for the query we sent. If we didn't get
		// a name error and we didn't get success,
		// the server is behaving incorrectly or
		// having temporary trouble.
		if h.RCode == dnsmessage.RCodeServerFailure {
			return errServerTemporarlyMisbehaving
		}
		return errServerMisbehaving
	}

	return nil
}

func skipToAnswer(p *dnsmessage.Parser, qtype dnsmessage.Type) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return errNoSuchHost
		}
		if err != nil {
			return errCannotUnmarshalDNSMessage
		}
		if h.Type == qtype {
			return nil
		}
		if err := p.SkipAnswer(); err != nil {
			return errCannotUnmarshalDNSMessage
		}
	}
}

func parseMsg(p dnsmessage.Parser) ([]net.IPAddr, error) {
	var lastErr error
	var addrs []net.IPAddr
	var cname dnsmessage.Name
loop:
	for {
		h, err := p.AnswerHeader()
		if err != nil && err != dnsmessage.ErrSectionDone {
			lastErr = errors.New("cannot marshal DNS message")
		}
		if err != nil {
			break
		}
		switch h.Type {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err != nil {
				lastErr = errCannotMarshalDNSMessage
				break loop
			}
			addrs = append(addrs, net.IPAddr{IP: net.IP(a.A[:])})

		case dnsmessage.TypeAAAA:
			aaaa, err := p.AAAAResource()
			if err != nil {
				lastErr = errCannotMarshalDNSMessage
				break loop
			}
			addrs = append(addrs, net.IPAddr{IP: net.IP(aaaa.AAAA[:])})

		default:
			if err := p.SkipAnswer(); err != nil {
				lastErr = errCannotMarshalDNSMessage
				break loop
			}
			continue
		}
		if cname.Length == 0 && h.Name.Length != 0 {
			cname = h.Name
		}
	}
	return addrs, lastErr
}

// https://golang.org/src/net/dnsclient_unix.go
// TODO: multiple server
func LookupIP(name string, dnsServer string) ([]net.IPAddr, error) {
	// qtypes := [...]dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	qtype := dnsmessage.TypeA
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, errCannotMarshalDNSMessage
	}
	q := dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}
	id, udpReq, _, err := newRequest(q)
	if err != nil {
		return nil, errCannotMarshalDNSMessage
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	// dialer.DialContext()
	c, err := dialer.Dial("udp", dnsServer)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write(udpReq); err != nil {
		return nil, err
	}
	p, h, err := dnsPacketRoundTrip(c, id, q, udpReq)
	c.Close()
	if err != nil {
		return nil, err
	}
	if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
		return nil, errInvalidDNSResponse
	}
	// if h.Truncated { // see RFC 5966
	// 	continue
	// }
	if err := checkHeader(&p, h); err != nil {
		return nil, err
	}
	err = skipToAnswer(&p, qtype)
	if err != nil {
		return nil, err
	}
	// parse response
	return parseMsg(p)
}
