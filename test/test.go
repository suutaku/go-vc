package test

import (
	"embed"
	"path"
)

var (
	//go:embed *
	testVector embed.FS
)

func GetTestResource(name string) ([]byte, error) {
	return testVector.ReadFile(path.Join("data", name))
}
