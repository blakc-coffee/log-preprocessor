package gen

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

func multilineSource() *Source {
	return &Source{
		Name: "multiline.log", IDPrefix: "ml", Term: TermLF,
		Full: 40, Sample: 40, Emit: emitMultiline,
	}
}

// MultilineStart is the RE2 pattern a `multiline:` source config needs to frame
// multiline.log correctly: a record begins at an ISO-8601 date at the start of
// a line, and every following line that does not match is a continuation.
const MultilineStart = `^\d{4}-\d{2}-\d{2}T`

// One manifest record is one whole event, not one physical line. The internal
// newlines are part of Raw - the framer appends continuation lines with their
// original terminators - and only the event's final terminator is excluded
// from byte_end. A framer that emitted these as separate records would fail
// the round-trip test.
var mlExceptions = []string{
	"java.net.SocketTimeoutException: connect timed out",
	"java.lang.IllegalStateException: tunnel already established",
	"javax.net.ssl.SSLHandshakeException: certificate expired",
	"java.io.IOException: broken pipe",
}

var mlFrames = []string{
	"com.example.vpn.SessionHandler.setup(SessionHandler.java:%d)",
	"com.example.vpn.Dispatcher.dispatch(Dispatcher.java:%d)",
	"com.example.vpn.TunnelPool.acquire(TunnelPool.java:%d)",
	"com.example.net.SocketFactory.connect(SocketFactory.java:%d)",
	"java.base/java.lang.Thread.run(Thread.java:%d)",
}

func emitMultiline(w *Writer, rng *rand.Rand, n int) {
	t := BaseTime
	for i := 0; i < n; i++ {
		t = t.Add(time.Duration(1+rng.IntN(60000)) * time.Millisecond)
		ts := t.Truncate(time.Millisecond)
		user := identityUsers[rng.IntN(len(identityUsers))]

		lines := []string{fmt.Sprintf(
			"%s ERROR [vpn-gw] com.example.vpn.SessionHandler - session setup failed for user %s",
			ts.Format("2006-01-02T15:04:05.000-07:00"), user)}

		// 3 to 8 lines per event, counting the header.
		for j := 0; j < 1+rng.IntN(5); j++ {
			lines = append(lines, "\tat "+fmt.Sprintf(mlFrames[rng.IntN(len(mlFrames))], 20+rng.IntN(400)))
		}
		lines = append(lines, "Caused by: "+mlExceptions[rng.IntN(len(mlExceptions))])
		lines = append(lines, fmt.Sprintf("\t... %d more", 1+rng.IntN(20)))

		w.EmitString(strings.Join(lines, "\n"), "", Expect{
			Expect: "parse", Vendor: "vpn_gateway", Time: ts, User: user,
		})
	}
}
