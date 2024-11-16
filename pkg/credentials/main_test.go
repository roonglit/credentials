package credentials

import (
	"os"
	"testing"
)

var executor IExecutor
var fileManager *MockFileManager

type MockCommandExecutor struct {
	CalledWithName string
	CalledWithArgs []string
}

func (m *MockCommandExecutor) Run(name string, args ...string) error {
	m.CalledWithName = name
	m.CalledWithArgs = args
	return nil
}

func NewMockCommandExecutor() IExecutor {
	return &MockCommandExecutor{}
}

type MockFileManager struct {
	CallWithPlaintext string
}

func (f *MockFileManager) Read(name string) ([]byte, error) {
	return []byte("develop:\n  access_token: token\n"), nil
}

func (f *MockFileManager) Write(file *os.File, plaintext []byte) (int, error) {
	plaintextStr := string(plaintext[:])
	f.CallWithPlaintext = plaintextStr
	return 0, nil
}

func TestMain(m *testing.M) {
	executor = NewMockCommandExecutor()
	fileManager = &MockFileManager{}
	os.Exit(m.Run())
}
