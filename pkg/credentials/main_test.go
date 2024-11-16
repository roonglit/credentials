package credentials

import (
	"fmt"
	"io"
	"os"
	"testing"
)

type MockViperConfigReader struct{}

func (m *MockViperConfigReader) UnmarshalKey(key string, rawVal any) error {
	if key == "error" {
		return fmt.Errorf("Unmarshal Error")
	}
	return nil
}

func (m *MockViperConfigReader) ReadConfig(in io.Reader) error {
	return nil
}

func NewMockViperConfigReader() IConfigReader {
	return &MockViperConfigReader{}
}

var configReader IConfigReader

func TestMain(m *testing.M) {
	configReader = NewMockViperConfigReader()
	os.Exit(m.Run())

}
