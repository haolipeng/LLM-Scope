// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

package transforms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/haolipeng/LLM-Scope/internal/event"
	"github.com/haolipeng/LLM-Scope/internal/logging"
)

// HTTPPCAPWriter writes decrypted HTTP messages as synthetic Ethernet/IPv4/TCP
// packets into a classic pcap file (Wireshark-compatible). It is intended to sit
// immediately after HTTPParser and before HTTPFilter so filtered-out traffic is
// still captured. Payload is raw_data when present, otherwise reconstructed from
// first_line, headers, and body.
//
// Multiplexing uses PID only (not TID): SSL_read and SSL_write often run on
// different threads, so splitting by TID would put requests and responses on
// separate synthetic TCP flows; a single flow per PID keeps Follow TCP Stream usable.
type HTTPPCAPWriter struct {
	path  string
	file  *os.File
	pw    *pcapgo.Writer
	inner *statefulAnalyzer

	mu    sync.Mutex
	flows map[flowKey]*flowState
}

type flowKey struct {
	pid uint32
}

// TCP sequence state per PID (one synthetic connection per process).
type flowState struct {
	clientNext uint32
	serverNext uint32
	clientPort layers.TCPPort
}

const (
	// snapLen is the pcap global max captured bytes per packet. Each record is one
	// full Ethernet frame; Wireshark rejects files where any packet exceeds this.
	// Large LLM/SSE bodies easily exceed 256KiB — use a generous cap (64MiB).
	snapLen          = 64 * 1024 * 1024
	synthClientIP    = 0x0a000001 // 10.0.0.1
	synthServerIP    = 0x0a000002 // 10.0.0.2
	synthServerPort  = 443
	initialClientSeq = 1000
	initialServerSeq = 2000
)

// NewHTTPPCAPWriter creates a writer for the given path. If path is empty, returns (nil, nil).
func NewHTTPPCAPWriter(path string) (*HTTPPCAPWriter, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("http pcap: create %q: %w", path, err)
	}
	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(snapLen, layers.LinkTypeEthernet); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("http pcap: write file header: %w", err)
	}
	w := &HTTPPCAPWriter{
		path:  path,
		file:  f,
		pw:    pw,
		flows: make(map[flowKey]*flowState),
	}
	w.inner = NewStatefulAnalyzer("http_pcap", StatefulOpts{
		OnEvent: w.handlePCAPEvent,
		OnClose: func(emit func(*event.Event)) { w.Close() },
	})
	return w, nil
}

func (w *HTTPPCAPWriter) handlePCAPEvent(ev *event.Event, emit func(*event.Event)) {
	if ev != nil {
		switch ev.Source {
		case "http_parser":
			if err := w.writeHTTPEvent(ev); err != nil {
				logging.Named("http_pcap").Warnf("write packet: %v", err)
			}
		case "sse_processor":
			if err := w.writeSSEEvent(ev); err != nil {
				logging.Named("http_pcap").Warnf("write sse packet: %v", err)
			}
		}
	}
	emit(ev)
}

func (w *HTTPPCAPWriter) Name() string { return "http_pcap" }

func (w *HTTPPCAPWriter) Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event {
	return w.inner.Process(ctx, in)
}

// Close flushes the pcap file. Safe to call multiple times.
func (w *HTTPPCAPWriter) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
}

func (w *HTTPPCAPWriter) writeHTTPEvent(ev *event.Event) error {
	var data map[string]interface{}
	if err := json.Unmarshal(ev.Data, &data); err != nil {
		return err
	}

	// Skip SSE response headers — the merged SSE body from sse_processor will
	// be written instead, avoiding duplicate HTTP 200 responses in the pcap.
	mt, _ := data["message_type"].(string)
	if mt == "response" {
		if headers, ok := data["headers"].(map[string]interface{}); ok {
			if ct := headerValueLower(headers, "content-type"); strings.Contains(ct, "text/event-stream") {
				return nil
			}
		}
	}

	payload, err := httpPayloadFromParserData(data)
	if err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}

	clientToServer := mt != "response"

	return w.writeTCPPayload(ev.TimestampNs, ev.PID, clientToServer, payload)
}

// writeSSEEvent handles sse_processor events by reconstructing a synthetic HTTP
// response from the merged SSE data and writing it as a server→client packet.
func (w *HTTPPCAPWriter) writeSSEEvent(ev *event.Event) error {
	var data map[string]interface{}
	if err := json.Unmarshal(ev.Data, &data); err != nil {
		return err
	}
	payload := buildSSEHTTPResponse(data)
	if len(payload) == 0 {
		return nil
	}
	// SSE responses are always server→client
	return w.writeTCPPayload(ev.TimestampNs, ev.PID, false, payload)
}

// formatSSEEvent 将单个 SSE 事件 map 格式化为 SSE 文本，写入 sb。
func formatSSEEvent(sb *strings.Builder, item interface{}) {
	m, ok := item.(map[string]interface{})
	if !ok {
		return
	}
	evt, _ := m["event"].(string)
	d, _ := m["data"].(string)
	if evt != "" {
		sb.WriteString("event: ")
		sb.WriteString(evt)
		sb.WriteString("\n")
	}
	if d != "" {
		sb.WriteString("data: ")
		sb.WriteString(d)
		sb.WriteString("\n")
	}
	if evt != "" || d != "" {
		sb.WriteString("\n")
	}
}

// buildSSEBody 从 sse_processor 事件数据中构建 HTTP 响应体和 Content-Type。
func buildSSEBody(data map[string]interface{}) (body string, contentType string) {
	if sseEvents, ok := data["sse_events"].([]interface{}); ok && len(sseEvents) > 0 {
		var sb strings.Builder
		for _, e := range sseEvents {
			formatSSEEvent(&sb, e)
		}
		if sb.Len() > 0 {
			return sb.String(), "text/event-stream"
		}
	}

	if text, _ := data["text_content"].(string); text != "" {
		return text, "text/plain"
	}
	if jsonContent, _ := data["json_content"].(string); jsonContent != "" {
		return jsonContent, "application/json"
	}
	return "", ""
}

// buildSSEHTTPResponse reconstructs an HTTP response from sse_processor event data:
// prefer rebuilding the SSE event stream from sse_events; fall back to text/json content.
func buildSSEHTTPResponse(data map[string]interface{}) []byte {
	bodyStr, contentType := buildSSEBody(data)
	if bodyStr == "" {
		return nil
	}

	var resp strings.Builder
	resp.WriteString("HTTP/1.1 200 OK\r\n")
	resp.WriteString("Content-Type: ")
	resp.WriteString(contentType)
	resp.WriteString("\r\n")
	resp.WriteString("Content-Length: ")
	resp.WriteString(strconv.Itoa(len(bodyStr)))
	resp.WriteString("\r\n\r\n")
	resp.WriteString(bodyStr)

	return []byte(resp.String())
}

func httpPayloadFromParserData(data map[string]interface{}) ([]byte, error) {
	if raw, ok := data["raw_data"].(string); ok && raw != "" {
		return embellishHTTPForReadability([]byte(raw)), nil
	}
	fl, _ := data["first_line"].(string)
	if fl == "" {
		return nil, fmt.Errorf("missing first_line and raw_data")
	}
	headers, _ := data["headers"].(map[string]interface{})
	body, _ := data["body"].(string)
	if body != "" {
		body = maybeIndentJSONBody(body, headers)
		if headers != nil {
			setContentLengthHeader(headers, len(body))
		}
	}

	var b strings.Builder
	b.WriteString(fl)
	b.WriteString("\r\n")

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(fmt.Sprint(headers[k]))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	if body != "" {
		b.WriteString(body)
	}
	return []byte(b.String()), nil
}

// embellishHTTPForReadability indents JSON bodies and fixes Content-Length in the header block.
func embellishHTTPForReadability(raw []byte) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return raw
	}
	head := raw[:idx]
	body := raw[idx+len(sep):]
	body = bytes.TrimSpace(body)
	if len(body) == 0 || !json.Valid(body) {
		return raw
	}
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return raw
	}
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return raw
	}
	headStr := updateContentLengthInHeaderBlock(string(head), len(pretty))
	out := make([]byte, 0, len(headStr)+4+len(pretty))
	out = append(out, headStr...)
	out = append(out, sep...)
	out = append(out, pretty...)
	return out
}

func updateContentLengthInHeaderBlock(headerBlock string, bodyLen int) string {
	lines := strings.Split(headerBlock, "\r\n")
	if len(lines) == 0 {
		return headerBlock
	}
	newCL := "Content-Length: " + strconv.Itoa(bodyLen)
	found := false
	for i := 1; i < len(lines); i++ {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(lines[i])), "content-length:") {
			lines[i] = newCL
			found = true
			break
		}
	}
	if !found {
		// Insert after first line (status/request line)
		out := make([]string, 0, len(lines)+1)
		out = append(out, lines[0])
		out = append(out, newCL)
		out = append(out, lines[1:]...)
		lines = out
	}
	return strings.Join(lines, "\r\n")
}

func maybeIndentJSONBody(body string, headers map[string]interface{}) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return body
	}
	ct := headerValueLower(headers, "content-type")
	jsonLike := strings.Contains(ct, "json") || json.Valid([]byte(body))
	if !jsonLike {
		return body
	}
	var v interface{}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return body
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return body
	}
	return string(out)
}

func headerValueLower(headers map[string]interface{}, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
		}
	}
	return ""
}

func setContentLengthHeader(headers map[string]interface{}, n int) {
	cl := strconv.Itoa(n)
	for k := range headers {
		if strings.EqualFold(k, "content-length") {
			headers[k] = cl
			return
		}
	}
	headers["Content-Length"] = cl
}

func (w *HTTPPCAPWriter) writeTCPPayload(timestampNs int64, pid uint32, clientToServer bool, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pw == nil || w.file == nil {
		return nil
	}

	key := flowKey{pid: pid}
	st, ok := w.flows[key]
	if !ok {
		st = &flowState{
			clientNext: initialClientSeq,
			serverNext: initialServerSeq,
			clientPort: synthClientPort(pid),
		}
		w.flows[key] = st
	}

	var (
		srcMAC, dstMAC   net.HardwareAddr
		srcIP, dstIP     net.IP
		srcPort, dstPort layers.TCPPort
		seq, ack         uint32
	)
	srcMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	if clientToServer {
		srcIP = ipv4(synthClientIP)
		dstIP = ipv4(synthServerIP)
		srcPort = st.clientPort
		dstPort = synthServerPort
		seq = st.clientNext
		ack = st.serverNext
		st.clientNext += uint32(len(payload))
	} else {
		srcMAC, dstMAC = dstMAC, srcMAC
		srcIP = ipv4(synthServerIP)
		dstIP = ipv4(synthClientIP)
		srcPort = synthServerPort
		dstPort = st.clientPort
		seq = st.serverNext
		ack = st.clientNext
		st.serverNext += uint32(len(payload))
	}

	raw, err := serializeEthIPv4TCP(srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, seq, ack, payload)
	if err != nil {
		return err
	}

	ts := time.Unix(0, timestampNs)
	if timestampNs <= 0 {
		ts = time.Now()
	}
	ci := gopacket.CaptureInfo{
		Timestamp:      ts,
		CaptureLength:  len(raw),
		Length:         len(raw),
		InterfaceIndex: 0,
	}
	return w.pw.WritePacket(ci, raw)
}

func synthClientPort(pid uint32) layers.TCPPort {
	return layers.TCPPort(32768 + (uint64(pid) % 28000))
}

func ipv4(u32 uint32) net.IP {
	return net.IPv4(byte(u32>>24), byte(u32>>16), byte(u32>>8), byte(u32))
}

func serializeEthIPv4TCP(
	srcMAC, dstMAC net.HardwareAddr,
	srcIP, dstIP net.IP,
	srcPort, dstPort layers.TCPPort,
	seq, ack uint32,
	payload []byte,
) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Seq:        seq,
		Ack:        ack,
		DataOffset: 5,
		PSH:        true,
		ACK:        true,
		Window:     64240,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
