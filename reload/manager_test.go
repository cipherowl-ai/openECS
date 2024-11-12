package reload

import (
	"context"
	"github.com/cipherowl-ai/addressdb/address"
	"os"
	"testing"
	"time"

	"github.com/cipherowl-ai/addressdb/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockNotifier is a mock implementation of the Notifier interface.
type MockNotifier struct {
	mock.Mock
}

func (m *MockNotifier) WatchForChange(ctx context.Context, callback func(string) error) error {
	args := m.Called(ctx, callback)
	return args.Error(0)
}

func (m *MockNotifier) Close() error {
	return m.Called().Error(0)
}

func setupTest(t *testing.T) (*store.BloomFilterStore, *MockNotifier, string) {
	addressHandler := &address.EVMAddressHandler{}
	generator, _ := store.NewBloomFilterStore(addressHandler, store.WithEstimates(1000, 0.001))
	filePath := os.TempDir() + "/testfile.gob"
	generator.SaveToFile(filePath)
	return generator, new(MockNotifier), filePath
}

func TestReloadManager_Start(t *testing.T) {
	generator, notifier, filePath := setupTest(t)
	defer os.Remove(filePath)

	address1 := "0x1234567890abcdef1234567890abcdef12345678"
	address2 := "0xabcdef1234567890abcdef1234567890abcdef12"
	generator.AddAddress(address1)
	generator.SaveToFile(filePath)

	store, _ := store.NewBloomFilterStoreFromFile(filePath, &address.EVMAddressHandler{})
	manager := NewReloadManager(store, notifier)

	var reloadFunc func(string) error
	notifier.On("WatchForChange", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			reloadFunc = args.Get(1).(func(string) error)
		}).Return(nil).Once()

	err := manager.Start(context.Background())
	assert.NoError(t, err)
	time.Sleep(150 * time.Millisecond)

	assertAddressCheck(t, store, address1, true)
	assertAddressCheck(t, store, address2, false)

	generator.AddAddress(address2)
	generator.SaveToFile(filePath)

	assert.NotNil(t, reloadFunc)
	err = reloadFunc(filePath)
	assert.NoError(t, err)

	assertAddressCheck(t, store, address1, true)
	assertAddressCheck(t, store, address2, true)

	notifier.AssertExpectations(t)
}

func assertAddressCheck(t *testing.T, store *store.BloomFilterStore, address string, expected bool) {
	got, err := store.CheckAddress(address)
	assert.NoError(t, err)
	assert.Equal(t, expected, got)
}

func TestReloadManager_Stop(t *testing.T) {
	store, notifier, _ := setupTest(t)
	manager := NewReloadManager(store, notifier)

	notifier.On("WatchForChange", mock.Anything, mock.Anything).Return(nil).Once()
	notifier.On("Close").Return(nil).Once()

	manager.Start(context.Background())
	err := manager.Stop()
	assert.NoError(t, err)

	notifier.AssertExpectations(t)
}
