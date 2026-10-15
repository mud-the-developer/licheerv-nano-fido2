package nanokit

import "testing"

func TestUserButtonTransitions(t *testing.T) {
	key := func(value int32) [3]int32 { return [3]int32{1, int32(UserButtonCode), value} }
	for _, tc := range []struct {
		name     string
		released bool
		events   [][3]int32
		approve  bool
		fail     bool
	}{
		{"fresh press from released", true, [][3]int32{key(1)}, true, false},
		{"held at request start", false, [][3]int32{key(1)}, false, false},
		{"held autorepeat", false, [][3]int32{key(2)}, false, false},
		{"release then new press", false, [][3]int32{key(0), key(1)}, true, false},
		{"release alone", false, [][3]int32{key(0)}, false, false},
		{"repeat while released", true, [][3]int32{key(2)}, false, false},
		{"wrong key", true, [][3]int32{{1, 1, 1}}, false, false},
		{"sync report", true, [][3]int32{{0, 0, 0}}, false, false},
		{"dropped events", true, [][3]int32{{0, 3, 0}}, false, true},
		{"invalid key value", true, [][3]int32{key(-1)}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := userButtonState{released: tc.released}
			var approve, fail bool
			for _, event := range tc.events {
				approve, fail = state.event(uint16(event[0]), uint16(event[1]), event[2])
				if approve || fail {
					break
				}
			}
			if approve != tc.approve || fail != tc.fail {
				t.Fatal("wrong approval transition")
			}
		})
	}
}
