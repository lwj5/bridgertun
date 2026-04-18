package wire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestEncodeDecode_NoBody(t *testing.T) {
	types := []string{
		TypeHello, TypePing, TypePong, TypeError,
		TypeResponseEnd, TypeRequestCancel,
	}
	for _, tp := range types {
		in := &Envelope{ID: "abc", Type: tp}
		b, err := Encode(in)
		if err != nil {
			t.Fatalf("%s: encode: %v", tp, err)
		}
		out, err := Decode(b)
		if err != nil {
			t.Fatalf("%s: decode: %v", tp, err)
		}
		if out.Body != nil {
			t.Fatalf("%s: expected nil Body, got %v", tp, out.Body)
		}
		if out.Type != tp || out.ID != "abc" {
			t.Fatalf("%s: fields not preserved: %+v", tp, out)
		}
	}
}

func TestEncodeDecode_SmallBody(t *testing.T) {
	body := []byte{0x00, 0x01, 0x7f, 0x80, 0xff, 0xfe, 0xc3, 0x28} // includes invalid UTF-8 (0xc3 0x28)
	in := &Envelope{ID: "id1", Type: TypeResponseChunk, Body: body}
	b, err := Encode(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := Decode(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(out.Body, body) {
		t.Fatalf("body mismatch: got %x want %x", out.Body, body)
	}
}

func TestEncodeDecode_LargeBody(t *testing.T) {
	sizes := []int{1 << 20, 8 << 20} // 1 MiB, 8 MiB
	for _, n := range sizes {
		body := make([]byte, n)
		for i := range body {
			body[i] = byte(i)
		}
		in := &Envelope{ID: "big", Type: TypeResponseChunk, Body: body}
		b, err := Encode(in)
		if err != nil {
			t.Fatalf("size=%d encode: %v", n, err)
		}
		out, err := Decode(b)
		if err != nil {
			t.Fatalf("size=%d decode: %v", n, err)
		}
		if !bytes.Equal(out.Body, body) {
			t.Fatalf("size=%d body mismatch", n)
		}
	}
}

func TestEncode_FrameTooLarge(t *testing.T) {
	body := make([]byte, MaxFrameSize) // definitely too big with a header
	in := &Envelope{ID: "x", Type: TypeResponseChunk, Body: body}
	_, err := Encode(in)
	if err == nil {
		t.Fatalf("expected error for oversized frame, got nil")
	}
}

func TestDecode_ShortFrame(t *testing.T) {
	_, err := Decode([]byte{0x00, 0x00})
	if err == nil {
		t.Fatalf("expected error for short frame")
	}
}

func TestDecode_HeaderLenOverflow(t *testing.T) {
	buf := make([]byte, 10)
	binary.BigEndian.PutUint32(buf[0:4], 1000) // claims 1000 bytes of header, only 6 available
	_, err := Decode(buf)
	if err == nil {
		t.Fatalf("expected error for header length overflow")
	}
}

func TestDecode_InvalidJSONHeader(t *testing.T) {
	garbage := []byte("{garbage")
	buf := make([]byte, 4+len(garbage))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(garbage))) //nolint:gosec // test fixture, len bounded
	copy(buf[4:], garbage)
	_, err := Decode(buf)
	if err == nil {
		t.Fatalf("expected error for malformed JSON header")
	}
}

func TestDecode_BodyAliasesInput(t *testing.T) {
	body := []byte{1, 2, 3, 4}
	in := &Envelope{ID: "alias", Type: TypeResponseChunk, Body: body}
	b, err := Encode(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := Decode(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Body) == 0 {
		t.Fatalf("empty Body after decode")
	}
	// Mutate the source buffer's body region; Decode must have returned a slice
	// aliasing that storage, so the mutation must be visible.
	b[len(b)-1] = 0xff
	if out.Body[len(out.Body)-1] != 0xff {
		t.Fatalf("Body does not alias input buffer; got %x", out.Body)
	}
}

func TestEncodeDecode_AllTypesRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		env  Envelope
	}{
		{"hello", Envelope{ID: "s1", Type: TypeHello, TunnelURL: "https://r/t/s1/"}},
		{"request", Envelope{
			ID:     "r1",
			Type:   TypeRequest,
			Method: "POST",
			Path:   "/v1/thing",
			Headers: map[string][]string{
				"Content-Type":    {"application/json"},
				"X-Forwarded-For": {"1.1.1.1", "2.2.2.2"},
			},
			Body: []byte(`{"k":"v"}`),
		}},
		{"response_head", Envelope{
			ID:      "r1",
			Type:    TypeResponseHead,
			Status:  200,
			Headers: map[string][]string{"Content-Type": {"text/plain"}},
		}},
		{"response_chunk", Envelope{ID: "r1", Type: TypeResponseChunk, Body: []byte("chunk")}},
		{"response_end", Envelope{ID: "r1", Type: TypeResponseEnd, EOF: true}},
		{"request_cancel", Envelope{ID: "r1", Type: TypeRequestCancel}},
		{"ping", Envelope{ID: "k1", Type: TypePing}},
		{"pong", Envelope{ID: "k1", Type: TypePong}},
		{"error", Envelope{ID: "r1", Type: TypeError, Error: "boom"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := Encode(&c.env)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			out, err := Decode(b)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if out.ID != c.env.ID || out.Type != c.env.Type || out.Method != c.env.Method ||
				out.Path != c.env.Path || out.Status != c.env.Status || out.EOF != c.env.EOF ||
				out.Error != c.env.Error || out.TunnelURL != c.env.TunnelURL {
				t.Fatalf("scalar field mismatch: got %+v want %+v", out, c.env)
			}
			if !bytes.Equal(out.Body, c.env.Body) {
				t.Fatalf("body mismatch: got %q want %q", out.Body, c.env.Body)
			}
			if len(c.env.Headers) != len(out.Headers) {
				t.Fatalf("headers length: got %d want %d", len(out.Headers), len(c.env.Headers))
			}
			for k, v := range c.env.Headers {
				if got := out.Headers[k]; strings.Join(got, ",") != strings.Join(v, ",") {
					t.Fatalf("header %q: got %v want %v", k, got, v)
				}
			}
		})
	}
}
