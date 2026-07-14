package recording

import (
	"testing"
	"time"
)

func TestSessionHubFanout(t *testing.T) {
	h := NewSessionHub()
	ch := h.Subscribe("s1")
	h.Broadcast("s1", []byte("hello"))
	select {
	case got := <-ch:
		if string(got) != "hello" {
			t.Fatalf("got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for broadcast")
	}
	h.Unsubscribe("s1", ch)
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected closed channel")
		}
	default:
		t.Fatal("channel should be closed")
	}
}
