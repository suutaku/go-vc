package testdata

import "embed"

var (
	//go:embed *
	testVector embed.FS
)

func GetTestResource(name string) ([]byte, error) {

	return testVector.ReadFile(name)
}
