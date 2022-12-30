package utils

import (
	"fmt"
	"strings"
	"time"
)

type FormatedTime struct {
	time.Time
}

func (ft *FormatedTime) UnmarshalJSON(data []byte) (err error) {
	if string(data) == "{}" {
		return nil
	}
	s := strings.Trim(string(data), "\"")
	ft.Time, err = time.Parse(time.RFC3339, string(s))
	return err
}

func (ft *FormatedTime) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", ft.Format(time.RFC3339))), nil
}
