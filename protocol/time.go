package protocol

import (
	"encoding/binary"
	"time"
)

const (
	TimestampSIze = 12
	Offset        = (2 << 61) + 10
)

type Tai64n [TimestampSIze]byte

func Now(t time.Time) (ts Tai64n) {
	now := t.Unix()
	secs := uint64(Offset) + uint64(now)
	nanos := uint32(t.Nanosecond()) &^ (0x1000000 - 1)

	binary.BigEndian.PutUint64(ts[:], secs)
	binary.BigEndian.PutUint32(ts[8:], nanos)
	return
}
