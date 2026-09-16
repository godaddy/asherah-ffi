package asherah

import "testing"

// FuzzMillisToSeconds is a formality: dividing by the constant 1000 can't
// panic or overflow strangely, but it locks in the truncation contract
// NewSessionFactory relies on (CryptoPolicy millis -> native config
// seconds) as a named, documented function instead of inline arithmetic.
func FuzzMillisToSeconds(f *testing.F) {
	f.Add(int64(0))
	f.Add(int64(999))
	f.Add(int64(1000))
	f.Add(int64(-1500))
	f.Add(int64(1<<63 - 1))
	f.Add(int64(-1 << 63))

	f.Fuzz(func(t *testing.T, millis int64) {
		secs := millisToSeconds(millis) // must not panic for any int64

		// The real precondition (NewSessionFactory only calls this for
		// millis > 0) is where the truncation contract matters: secs is
		// the floor, and the dropped remainder is in [0, 1000).
		if millis < 0 {
			return
		}
		if secs*1000 > millis {
			t.Fatalf("millisToSeconds(%d) = %d, secs*1000 exceeds millis", millis, secs)
		}
		if diff := millis - secs*1000; diff < 0 || diff >= 1000 {
			t.Fatalf("millisToSeconds(%d) = %d, remainder %d out of [0,1000)", millis, secs, diff)
		}
	})
}
