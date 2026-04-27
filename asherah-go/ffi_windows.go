//go:build windows

package asherah

import (
	"fmt"
	"syscall"

	"github.com/ebitengine/purego"
)

func openLibrary(path string) (uintptr, error) {
	h, err := syscall.LoadLibrary(path)
	if err != nil {
		return 0, fmt.Errorf("LoadLibrary(%s): %w", path, err)
	}
	return uintptr(h), nil
}

func loadSymbols(lib uintptr) error {
	var err error
	reg := func(fptr any, name string) {
		if err != nil {
			return
		}
		purego.RegisterLibFunc(fptr, lib, name)
	}

	reg(&fnFactoryNewFromEnv, "asherah_factory_new_from_env")
	reg(&fnFactoryNewWithConfig, "asherah_factory_new_with_config")
	reg(&fnFactoryFree, "asherah_factory_free")
	reg(&fnFactoryGetSession, "asherah_factory_get_session")
	reg(&fnSessionFree, "asherah_session_free")
	reg(&fnEncryptToJSON, "asherah_encrypt_to_json")
	reg(&fnDecryptFromJSON, "asherah_decrypt_from_json")
	reg(&fnBufferFree, "asherah_buffer_free")
	reg(&fnLastErrorMessage, "asherah_last_error_message")
	reg(&fnSetLogHook, "asherah_set_log_hook")
	reg(&fnClearLogHook, "asherah_clear_log_hook")
	reg(&fnSetMetricsHook, "asherah_set_metrics_hook")
	reg(&fnClearMetricsHook, "asherah_clear_metrics_hook")

	return err
}
