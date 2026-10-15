package nanokit

const UserButtonCode uint16 = 431

type userButtonState struct{ released bool }

// Only a fresh down after release approves; repeats and unrelated keys do not.
func (s *userButtonState) event(eventType, code uint16, value int32) (approve, fail bool) {
	if eventType == 0 && code == 3 { // SYN_DROPPED: event history cannot be trusted.
		return false, true
	}
	if eventType != 1 || code != UserButtonCode {
		return false, false
	}
	switch value {
	case 0:
		s.released = true
	case 1:
		fresh := s.released
		s.released = false
		return fresh, false
	case 2: // Autorepeat is not a fresh press.
	default:
		return false, true
	}
	return false, false
}
