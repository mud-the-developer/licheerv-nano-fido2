package nanokit

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestReportRead(t *testing.T) {
	b := bytes.Repeat([]byte{0x42}, 64)
	got, err := ReadReport(bytes.NewReader(b))
	if err != nil || !bytes.Equal(got, b) {
		t.Fatal("report mismatch", err)
	}
}
func TestShortReportRejected(t *testing.T) {
	if _, err := ReadReport(bytes.NewReader(make([]byte, 63))); err == nil {
		t.Fatal("short report accepted")
	}
}
func TestReportEOF(t *testing.T) {
	if _, err := ReadReport(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}
func TestReportWrite(t *testing.T) {
	var out bytes.Buffer
	if err := WriteReport(&out, make([]byte, 64)); err != nil || out.Len() != 64 {
		t.Fatal(err)
	}
}
func TestBadWriteSize(t *testing.T) {
	if err := WriteReport(io.Discard, make([]byte, 65)); err == nil {
		t.Fatal("invalid report accepted")
	}
}
func TestShortWriteRejected(t *testing.T) {
	if err := WriteReport(shortWriter{}, make([]byte, 64)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}
