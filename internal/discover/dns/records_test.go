package dns

import (
	"context"
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

func TestNormalizeDnsxResolversTrimsAndNormalizesAddresses(t *testing.T) {
	input := []string{" 8.8.8.8 ", " tcp:1.1.1.1 ", "udp:9.9.9.9:5353 "}
	expected := []string{"udp:8.8.8.8:53", "tcp:1.1.1.1:53", "udp:9.9.9.9:5353"}

	actual := normalizeDnsxResolvers(input, false)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

func TestNormalizeDnsxResolversForcesTCP(t *testing.T) {
	input := []string{"udp:8.8.8.8", "tcp:1.1.1.1", "9.9.9.9"}
	expected := []string{"tcp:8.8.8.8:53", "tcp:1.1.1.1:53", "tcp:9.9.9.9:53"}

	actual := normalizeDnsxResolvers(input, true)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

func TestGetDNSRecordsPreservesTypedAnswersGolden(t *testing.T) {
	resolver := startAuthoritativeDNSFixture(t)
	records, err := getDNSRecords(
		context.Background(),
		"example.test",
		[]uint16{dns.TypeA, dns.TypeMX, dns.TypeSRV, dns.TypeCAA, dns.TypeTXT},
		[]string{"udp:" + resolver},
		5,
	)
	if err != nil {
		t.Fatalf("query local DNS fixture: %v", err)
	}

	actual, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatalf("marshal DNS records: %v", err)
	}
	const expected = `[
  {
    "name": "example.test",
    "ttl": 60,
    "type": "A",
    "value": "192.0.2.10"
  },
  {
    "name": "example.test",
    "ttl": 120,
    "type": "A",
    "value": "192.0.2.11"
  },
  {
    "name": "example.test",
    "ttl": 300,
    "type": "MX",
    "value": "10 mail.example.test."
  },
  {
    "name": "_https._tcp.example.test",
    "ttl": 45,
    "type": "SRV",
    "value": "5 20 443 service.example.test."
  },
  {
    "name": "example.test",
    "ttl": 600,
    "type": "CAA",
    "value": "0 issue \"letsencrypt.org\""
  },
  {
    "name": "example.test",
    "ttl": 90,
    "type": "TXT",
    "value": "\"segment-one\" \"segment-two\""
  }
]`
	if string(actual) != expected {
		t.Fatalf("DNS record golden mismatch\nexpected:\n%s\nactual:\n%s", expected, actual)
	}
}

func TestGetDNSRecordsDoesNotRetryValidEmptyAnswers(t *testing.T) {
	var queryCount atomic.Int32
	resolver := startDNSTestServer(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		queryCount.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		_ = writer.WriteMsg(response)
	}))

	records, err := getDNSRecords(
		context.Background(),
		"empty.example.test",
		[]uint16{dns.TypeA, dns.TypeMX},
		[]string{"udp:" + resolver},
		5,
	)
	if err != nil {
		t.Fatalf("query valid empty answers: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no records, got %v", records)
	}
	if queryCount.Load() != 2 {
		t.Fatalf("expected one query per record type, got %d", queryCount.Load())
	}
}

func TestGetDNSRecordsRetainsRetriesForResolverFailures(t *testing.T) {
	var queryCount atomic.Int32
	resolver := startDNSTestServer(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		queryCount.Add(1)
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeServerFailure)
		_ = writer.WriteMsg(response)
	}))

	records, err := getDNSRecords(
		context.Background(),
		"failure.example.test",
		[]uint16{dns.TypeA},
		[]string{"udp:" + resolver},
		5,
	)
	if err != nil {
		t.Fatalf("query resolver failures: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no records, got %v", records)
	}
	if queryCount.Load() != int32(dnsx.DefaultOptions.MaxRetries) {
		t.Fatalf("expected %d resolver attempts, got %d", dnsx.DefaultOptions.MaxRetries, queryCount.Load())
	}
}

func TestGetDNSRecordsKeepsRecordsAndContinuesAfterTypeTimeout(t *testing.T) {
	resolver := startDNSTestServer(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		question := request.Question[0]
		if question.Qtype == dns.TypeMX {
			return
		}
		response := new(dns.Msg)
		response.SetReply(request)
		switch question.Qtype {
		case dns.TypeA:
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("192.0.2.25"),
			}}
		case dns.TypeTXT:
			response.Answer = []dns.RR{&dns.TXT{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 90},
				Txt: []string{"after-timeout"},
			}}
		}
		_ = writer.WriteMsg(response)
	}))

	records, err := getDNSRecords(
		context.Background(),
		"partial.example.test",
		[]uint16{dns.TypeA, dns.TypeMX, dns.TypeTXT},
		[]string{"udp:" + resolver},
		1,
	)
	if err == nil || !strings.Contains(err.Error(), "MX query failed") || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected an MX timeout, got %v", err)
	}
	if len(records) != 2 || records[0].Value != "192.0.2.25" || records[1].Value != `"after-timeout"` {
		t.Fatalf("expected records before and after the MX timeout, got %v", records)
	}
}

func TestCollectDNSRecordsStopsTimedOutClientBeforeNextType(t *testing.T) {
	var mxQueries atomic.Int32
	var txtQueries atomic.Int32
	resolver := startDNSTestServer(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		question := request.Question[0]
		response := new(dns.Msg)
		response.SetReply(request)
		switch question.Qtype {
		case dns.TypeMX:
			mxQueries.Add(1)
			return
		case dns.TypeTXT:
			txtQueries.Add(1)
			response.Answer = []dns.RR{&dns.TXT{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 90},
				Txt: []string{"after-timeout"},
			}}
			_ = writer.WriteMsg(response)
		}
	}))

	options := dnsx.DefaultOptions
	options.BaseResolvers = []string{"udp:" + resolver}
	options.MaxRetries = 1
	options.Timeout = 80 * time.Millisecond
	client, err := dnsx.New(options)
	if err != nil {
		t.Fatalf("create DNS client: %v", err)
	}

	records, err := collectDNSRecords(
		context.Background(),
		client,
		"isolated.example.test",
		[]uint16{dns.TypeMX, dns.TypeTXT},
		10*time.Millisecond,
		2,
	)
	if err == nil || !strings.Contains(err.Error(), "MX query failed") {
		t.Fatalf("expected an MX timeout, got %v", err)
	}
	if len(records) != 1 || records[0].Type != "TXT" || records[0].Value != `"after-timeout"` {
		t.Fatalf("expected the TXT record after the MX timeout, got %v", records)
	}

	// Let the first client's blocked resolver call finish. Before client
	// isolation, its next retry observed the shared TXT QuestionTypes mutation
	// and issued a second TXT query after this function had reported the MX
	// timeout.
	time.Sleep(120 * time.Millisecond)
	if mxQueries.Load() != 1 || txtQueries.Load() != 1 {
		t.Fatalf("expected one isolated query per type, got MX=%d TXT=%d", mxQueries.Load(), txtQueries.Load())
	}
}

func startAuthoritativeDNSFixture(t *testing.T) string {
	t.Helper()
	return startDNSTestServer(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		if len(request.Question) == 0 {
			_ = writer.WriteMsg(response)
			return
		}
		var recordStrings []string
		switch request.Question[0].Qtype {
		case dns.TypeA:
			recordStrings = []string{
				"example.test. 60 IN A 192.0.2.10",
				"example.test. 120 IN A 192.0.2.11",
			}
		case dns.TypeMX:
			recordStrings = []string{"example.test. 300 IN MX 10 mail.example.test."}
		case dns.TypeSRV:
			recordStrings = []string{"_https._tcp.example.test. 45 IN SRV 5 20 443 service.example.test."}
		case dns.TypeCAA:
			recordStrings = []string{`example.test. 600 IN CAA 0 issue "letsencrypt.org"`}
		case dns.TypeTXT:
			recordStrings = []string{`example.test. 90 IN TXT "segment-one" "segment-two"`}
		}
		for _, value := range recordStrings {
			record, parseErr := dns.NewRR(value)
			if parseErr != nil {
				t.Errorf("parse DNS fixture record %q: %v", value, parseErr)
				continue
			}
			response.Answer = append(response.Answer, record)
		}
		_ = writer.WriteMsg(response)
	}))
}

func startDNSTestServer(t *testing.T, handler dns.Handler) string {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for DNS fixture: %v", err)
	}

	server := &dns.Server{PacketConn: packetConn, Handler: handler}
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
		if serveErr := <-serveErrors; serveErr != nil && !strings.Contains(serveErr.Error(), "closed") {
			t.Errorf("DNS fixture server: %v", serveErr)
		}
	})
	return packetConn.LocalAddr().String()
}
