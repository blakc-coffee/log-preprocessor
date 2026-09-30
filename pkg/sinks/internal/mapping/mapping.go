// Package mapping extracts the common SIEM fields from an OCSF event without
// mutating the event or discarding its remaining fields.
package mapping

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dark-14100/sluice/pkg/types"
)

// Fields is the exporter-neutral projection of a normalized event.
type Fields struct {
	EventTime                                  time.Time
	SrcIP, DstIP                               string
	SrcPort, DstPort                           int
	Protocol, Action, Outcome                  string
	User, Host, Message                        string
	BytesIn, BytesOut                          int64
	SeverityID, ActionID, ActivityID, ClassUID int32
}

// Extract returns common fields while leaving the source OCSF map untouched.
func Extract(e types.NormalizedEvent) Fields {
	t := e.ReceivedAt
	if e.EventTime != nil {
		t = *e.EventTime
	}
	f := Fields{EventTime: t.UTC()}
	f.SrcIP = text(e.OCSF, "src_endpoint.ip", "source.ip", "src_ip")
	f.DstIP = text(e.OCSF, "dst_endpoint.ip", "destination.ip", "dst_ip")
	f.SrcPort = integer(e.OCSF, "src_endpoint.port", "source.port", "src_port")
	f.DstPort = integer(e.OCSF, "dst_endpoint.port", "destination.port", "dst_port")
	f.Protocol = text(e.OCSF, "protocol", "network.transport", "proto")
	f.Action = text(e.OCSF, "action", "event.action")
	f.Outcome = text(e.OCSF, "status", "event.outcome")
	f.User = text(e.OCSF, "user.name", "actor.user.name", "user")
	f.Host = text(e.OCSF, "device.hostname", "host.name", "host")
	f.Message = text(e.OCSF, "message", "msg")
	f.BytesIn = int64value(e.OCSF, "traffic.bytes_in", "network.bytes_in", "bytes_in")
	f.BytesOut = int64value(e.OCSF, "traffic.bytes_out", "network.bytes_out", "bytes_out")
	f.SeverityID = int32(integer(e.OCSF, "severity_id"))
	f.ActionID = int32(integer(e.OCSF, "action_id"))
	f.ActivityID = int32(integer(e.OCSF, "activity_id"))
	f.ClassUID = int32(integer(e.OCSF, "class_uid"))
	return f
}

// CloneMap makes a JSON-safe deep copy suitable for exporter augmentation.
func CloneMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	b, err := json.Marshal(in)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		return map[string]any{}
	}
	return out
}

func lookup(m map[string]any, path string) (any, bool) {
	if v, ok := m[path]; ok {
		return v, true
	}
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func text(m map[string]any, paths ...string) string {
	for _, p := range paths {
		if v, ok := lookup(m, p); ok {
			if s, ok := v.(string); ok {
				return s
			}
			if v != nil {
				return fmt.Sprint(v)
			}
		}
	}
	return ""
}

func integer(m map[string]any, paths ...string) int { return int(int64value(m, paths...)) }
func int64value(m map[string]any, paths ...string) int64 {
	for _, p := range paths {
		v, ok := lookup(m, p)
		if !ok {
			continue
		}
		switch n := v.(type) {
		case int:
			return int64(n)
		case int32:
			return int64(n)
		case int64:
			return n
		case uint64:
			if n <= uint64(^uint64(0)>>1) {
				return int64(n)
			}
		case float64:
			return int64(n)
		case json.Number:
			i, _ := n.Int64()
			return i
		case string:
			i, err := strconv.ParseInt(n, 10, 64)
			if err == nil {
				return i
			}
		}
	}
	return 0
}
