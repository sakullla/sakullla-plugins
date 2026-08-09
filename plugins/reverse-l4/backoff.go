package reversel4

import (
	"errors"
	"time"
)

// Backoff is deterministic so retry scheduling is observable and testable.
// Hosts may add bounded jitter when their public typed session contract exists.
type Backoff struct {
	Minimum time.Duration
	Maximum time.Duration
	Factor  uint32
}

func (backoff Backoff) Validate() error {
	if backoff.Minimum <= 0 || backoff.Maximum < backoff.Minimum || backoff.Factor < 2 {
		return errors.New("backoff requires 0 < minimum <= maximum and factor >= 2")
	}
	return nil
}

func (backoff Backoff) Delay(attempt uint32) time.Duration {
	if backoff.Validate() != nil {
		return 0
	}
	delay := backoff.Minimum
	for current := uint32(0); current < attempt; current++ {
		if delay >= backoff.Maximum/time.Duration(backoff.Factor) {
			return backoff.Maximum
		}
		delay *= time.Duration(backoff.Factor)
	}
	if delay > backoff.Maximum {
		return backoff.Maximum
	}
	return delay
}
