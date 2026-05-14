// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

package transforms

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/haolipeng/LLM-Scope/internal/event"
)

func TestHTTPPayloadFromParserData_rawData(t *testing.T) {
	data := map[string]interface{}{
		"raw_data": "GET /x HTTP/1.1\r\nHost: a\r\n\r\n",
	}
	b, err := httpPayloadFromParserData(data)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "GET /x HTTP/1.1\r\nHost: a\r\n\r\n" {
		t.Fatalf("got %q", b)
	}
}

func TestHTTPPayloadFromParserData_reconstructed(t *testing.T) {
	data := map[string]interface{}{
		"first_line": "POST /api HTTP/1.1",
		"headers": map[string]interface{}{
			"Host": "example.com",
		},
		"body": "{}",
	}
	b, err := httpPayloadFromParserData(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 20 {
		t.Fatalf("payload too short: %q", b)
	}
}

func TestEmbellishHTTPForReadability_JSON(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"a\":1,\"b\":2}"
	out := embellishHTTPForReadability([]byte(raw))
	if !bytes.Contains(out, []byte("\n  \"a\"")) {
		t.Fatalf("expected indented JSON in payload, got %q", string(out))
	}
	if !bytes.Contains(out, []byte("Content-Length:")) {
		t.Fatal("missing Content-Length after pretty-print")
	}
}

func TestHTTPPCAPWriter_samePIDDifferentTID_sharesFlow(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "out.pcap")
	w, err := NewHTTPPCAPWriter(path)
	if err != nil || w == nil {
		t.Fatal(err)
	}
	makeEv := func(tid float64, mt, raw string) *event.Event {
		p := map[string]interface{}{"tid": tid, "message_type": mt, "raw_data": raw}
		d, _ := json.Marshal(p)
		return &event.Event{TimestampNs: time.Now().UnixNano(), Source: "http_parser", PID: 4242, Data: d}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan *event.Event, 4)
	out := w.Process(ctx, in)
	in <- makeEv(111, "request", "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	in <- makeEv(222, "response", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	close(in)
	for range out {
	}
	w.Close()

	f, _ := os.Open(path)
	defer f.Close()
	r, _ := pcapgo.NewReader(f)
	n := 0
	for {
		_, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		n++
	}
	if n != 2 {
		t.Fatalf("expected 2 packets (req+resp same PID flow), got %d", n)
	}
}

func TestHTTPPCAPWriter_writesPackets(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "out.pcap")

	w, err := NewHTTPPCAPWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if w == nil {
		t.Fatal("expected non-nil writer")
	}

	payload := map[string]interface{}{
		"tid":          float64(42),
		"message_type": "request",
		"raw_data":     "GET / HTTP/1.1\r\nHost: t\r\n\r\n",
	}
	raw, _ := json.Marshal(payload)
	ev := &event.Event{
		TimestampNs: time.Now().UnixNano(),
		Source:      "http_parser",
		PID:         1000,
		Comm:        "test",
		Data:        raw,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan *event.Event, 2)
	out := w.Process(ctx, in)
	in <- ev
	close(in)
	for range out {
	}
	w.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		if ci.CaptureLength == 0 && len(data) == 0 {
			break
		}
		n++
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if pkt.ErrorLayer() != nil {
			t.Fatalf("parse packet: %v", pkt.ErrorLayer().Error())
		}
	}
	if n != 1 {
		t.Fatalf("expected 1 packet in pcap, got %d", n)
	}
}

func TestHTTPPCAPWriter_requestAndSSEResponse(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "out.pcap")
	w, err := NewHTTPPCAPWriter(path)
	if err != nil || w == nil {
		t.Fatal(err)
	}

	// HTTP request event (from http_parser)
	reqPayload := map[string]interface{}{
		"tid":          float64(111),
		"message_type": "request",
		"raw_data":     "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"claude-3\"}",
	}
	reqData, _ := json.Marshal(reqPayload)
	reqEv := &event.Event{
		TimestampNs: time.Now().UnixNano(),
		Source:      "http_parser",
		PID:         5000,
		Data:        reqData,
	}

	// SSE response event (from sse_processor)
	ssePayload := map[string]interface{}{
		"connection_id": "5000:111:0",
		"message_id":    "msg_123",
		"text_content":  "Hello world",
		"json_content":  "",
		"sse_events": []map[string]interface{}{
			{"event": "message_start", "data": "{\"type\":\"message_start\"}"},
			{"event": "content_block_delta", "data": "{\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello world\"}}"},
			{"event": "message_stop", "data": "{\"type\":\"message_stop\"}"},
		},
		"event_count": 3,
		"total_size":  11,
	}
	sseData, _ := json.Marshal(ssePayload)
	sseEv := &event.Event{
		TimestampNs: time.Now().UnixNano(),
		Source:      "sse_processor",
		PID:         5000,
		Data:        sseData,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan *event.Event, 4)
	out := w.Process(ctx, in)
	in <- reqEv
	in <- sseEv
	close(in)
	for range out {
	}
	w.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}

	n := 0
	hasRequest := false
	hasResponse := false
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		n++
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if pkt.ErrorLayer() != nil {
			t.Fatalf("parse packet %d: %v", n, pkt.ErrorLayer().Error())
		}
		if app := pkt.ApplicationLayer(); app != nil {
			payload := string(app.Payload())
			if bytes.Contains([]byte(payload), []byte("POST /v1/messages")) {
				hasRequest = true
			}
			if bytes.Contains([]byte(payload), []byte("HTTP/1.1 200 OK")) {
				hasResponse = true
			}
		}
	}
	if n != 2 {
		t.Fatalf("expected 2 packets (request + sse response), got %d", n)
	}
	if !hasRequest {
		t.Fatal("pcap missing HTTP request packet")
	}
	if !hasResponse {
		t.Fatal("pcap missing HTTP response packet")
	}
}

func TestHTTPPCAPWriter_skipsSSEResponseHeader(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "out.pcap")
	w, err := NewHTTPPCAPWriter(path)
	if err != nil || w == nil {
		t.Fatal(err)
	}

	// HTTP request (should be written)
	reqPayload := map[string]interface{}{
		"message_type": "request",
		"raw_data":     "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n{}",
	}
	reqData, _ := json.Marshal(reqPayload)
	reqEv := &event.Event{
		TimestampNs: time.Now().UnixNano(),
		Source:      "http_parser",
		PID:         6000,
		Data:        reqData,
	}

	// SSE response header from http_parser (should be skipped)
	sseHeaderPayload := map[string]interface{}{
		"message_type": "response",
		"first_line":   "HTTP/1.1 200 OK",
		"headers": map[string]interface{}{
			"content-type": "text/event-stream",
		},
		"body": "",
	}
	sseHeaderData, _ := json.Marshal(sseHeaderPayload)
	sseHeaderEv := &event.Event{
		TimestampNs: time.Now().UnixNano(),
		Source:      "http_parser",
		PID:         6000,
		Data:        sseHeaderData,
	}

	// Merged SSE response from sse_processor (should be written)
	ssePayload := map[string]interface{}{
		"sse_events": []map[string]interface{}{
			{"event": "message_start", "data": "{\"type\":\"message_start\"}"},
		},
	}
	sseData, _ := json.Marshal(ssePayload)
	sseEv := &event.Event{
		TimestampNs: time.Now().UnixNano(),
		Source:      "sse_processor",
		PID:         6000,
		Data:        sseData,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan *event.Event, 4)
	out := w.Process(ctx, in)
	in <- reqEv
	in <- sseHeaderEv
	in <- sseEv
	close(in)
	for range out {
	}
	w.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		_, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		n++
	}
	// Expect 2 packets: request + merged SSE response. The SSE header should be skipped.
	if n != 2 {
		t.Fatalf("expected 2 packets (request + merged SSE), got %d", n)
	}
}
