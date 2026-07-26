package proxy

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
)

const (
	eventStreamPreludeLength    = 12
	eventStreamMessageCRCLength = 4
	eventStreamMaxHeadersLength = 128 * 1024
	eventStreamMaxPayloadLength = 16 * 1024 * 1024
)

type eventStreamMessage struct {
	headers map[string]string
	payload []byte
}

type upstreamEventStreamError struct {
	messageType            string
	code                   string
	message                string
	reason                 string
	retryAfterMilliseconds string
}

func (e *upstreamEventStreamError) Error() string {
	parts := []string{"upstream event stream " + e.messageType}
	if e.code != "" {
		parts = append(parts, e.code)
	}
	if e.message != "" {
		parts = append(parts, e.message)
	}
	if e.reason != "" {
		parts = append(parts, "reason="+e.reason)
	}
	if e.retryAfterMilliseconds != "" {
		parts = append(parts, "retryAfterMilliseconds="+e.retryAfterMilliseconds)
	}
	return strings.Join(parts, ": ")
}

func newUpstreamEventStreamError(messageType, code, headerMessage string, payload map[string]interface{}) error {
	message := strings.TrimSpace(headerMessage)
	if message == "" {
		message = firstStringField(payload, "message", "errorMessage", "error")
	}

	retryAfter := ""
	if value, ok := payload["retryAfterMilliseconds"]; ok && value != nil {
		retryAfter = fmt.Sprint(value)
	}

	return &upstreamEventStreamError{
		messageType:            messageType,
		code:                   strings.TrimSpace(code),
		message:                message,
		reason:                 firstStringField(payload, "reason"),
		retryAfterMilliseconds: retryAfter,
	}
}

// readEventStreamMessage validates and decodes one AWS EventStream envelope.
// A nil message and nil error means a clean EOF between messages.
func readEventStreamMessage(body io.Reader) (*eventStreamMessage, error) {
	prelude := make([]byte, eventStreamPreludeLength)
	if _, err := io.ReadFull(body, prelude); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, fmt.Errorf("read event stream prelude: %w", err)
	}

	wantPreludeCRC := binary.BigEndian.Uint32(prelude[8:12])
	gotPreludeCRC := crc32.ChecksumIEEE(prelude[:8])
	if gotPreludeCRC != wantPreludeCRC {
		return nil, fmt.Errorf("event stream prelude CRC mismatch: got %08x, want %08x", gotPreludeCRC, wantPreludeCRC)
	}

	totalLength := binary.BigEndian.Uint32(prelude[0:4])
	headersLength := binary.BigEndian.Uint32(prelude[4:8])
	if totalLength < eventStreamPreludeLength+eventStreamMessageCRCLength {
		return nil, fmt.Errorf("invalid event stream total length %d", totalLength)
	}
	if headersLength > eventStreamMaxHeadersLength {
		return nil, fmt.Errorf("event stream headers length %d exceeds limit %d", headersLength, eventStreamMaxHeadersLength)
	}
	if uint64(headersLength)+eventStreamPreludeLength+eventStreamMessageCRCLength > uint64(totalLength) {
		return nil, fmt.Errorf("invalid event stream headers length %d for total length %d", headersLength, totalLength)
	}
	payloadLength := totalLength - headersLength - eventStreamPreludeLength - eventStreamMessageCRCLength
	if payloadLength > eventStreamMaxPayloadLength {
		return nil, fmt.Errorf("event stream payload length %d exceeds limit %d", payloadLength, eventStreamMaxPayloadLength)
	}

	remaining := make([]byte, int(totalLength)-eventStreamPreludeLength)
	if _, err := io.ReadFull(body, remaining); err != nil {
		return nil, fmt.Errorf("read event stream message: %w", err)
	}

	messageCRCOffset := len(remaining) - eventStreamMessageCRCLength
	wantMessageCRC := binary.BigEndian.Uint32(remaining[messageCRCOffset:])
	checksum := crc32.NewIEEE()
	_, _ = checksum.Write(prelude)
	_, _ = checksum.Write(remaining[:messageCRCOffset])
	gotMessageCRC := checksum.Sum32()
	if gotMessageCRC != wantMessageCRC {
		return nil, fmt.Errorf("event stream message CRC mismatch: got %08x, want %08x", gotMessageCRC, wantMessageCRC)
	}

	headersEnd := int(headersLength)
	headers, err := parseEventStreamHeaders(remaining[:headersEnd])
	if err != nil {
		return nil, err
	}
	payload := remaining[headersEnd:messageCRCOffset]
	return &eventStreamMessage{headers: headers, payload: payload}, nil
}

func parseEventStreamHeaders(encoded []byte) (map[string]string, error) {
	headers := make(map[string]string)
	for offset := 0; offset < len(encoded); {
		nameLength := int(encoded[offset])
		offset++
		if nameLength == 0 || offset+nameLength+1 > len(encoded) {
			return nil, fmt.Errorf("malformed event stream header name at offset %d", offset-1)
		}
		name := string(encoded[offset : offset+nameLength])
		offset += nameLength
		valueType := encoded[offset]
		offset++

		switch valueType {
		case 0, 1: // boolean true / false: no value bytes
		case 2:
			if offset+1 > len(encoded) {
				return nil, fmt.Errorf("malformed byte header %q", name)
			}
			offset++
		case 3:
			if offset+2 > len(encoded) {
				return nil, fmt.Errorf("malformed int16 header %q", name)
			}
			offset += 2
		case 4:
			if offset+4 > len(encoded) {
				return nil, fmt.Errorf("malformed int32 header %q", name)
			}
			offset += 4
		case 5, 8:
			if offset+8 > len(encoded) {
				return nil, fmt.Errorf("malformed int64 header %q", name)
			}
			offset += 8
		case 6, 7:
			if offset+2 > len(encoded) {
				return nil, fmt.Errorf("malformed variable-length header %q", name)
			}
			valueLength := int(binary.BigEndian.Uint16(encoded[offset : offset+2]))
			offset += 2
			if offset+valueLength > len(encoded) {
				return nil, fmt.Errorf("malformed variable-length header %q", name)
			}
			if valueType == 7 {
				headers[name] = string(encoded[offset : offset+valueLength])
			}
			offset += valueLength
		case 9:
			if offset+16 > len(encoded) {
				return nil, fmt.Errorf("malformed UUID header %q", name)
			}
			offset += 16
		default:
			return nil, fmt.Errorf("unsupported event stream header type %d for %q", valueType, name)
		}
	}
	return headers, nil
}
