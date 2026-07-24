//go:build !darwin

package keystore

func newPlatformKeyStore() platformKeyStore {
	return goKeyringStore{storeErrorsUnavailable: true}
}
