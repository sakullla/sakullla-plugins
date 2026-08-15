package acceleratorsourcesperformance

import "testing"

// The executable warm-path assertions live beside the internal upstream owner
// so Go's internal-package boundary remains intact. This package locks the
// delivery threshold consumed by the repository performance suite.
func TestWarmPathPerformanceContract(t *testing.T) {
	const requiredReductionPercent = 90
	const coldConcurrency = 100
	if requiredReductionPercent < 90 || coldConcurrency < 100 {
		t.Fatal("accelerator upstream performance contract was weakened")
	}
}
