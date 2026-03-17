//go:build !windows

package asherah

import "github.com/ebitengine/purego"

func openLibrary(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}

func loadSymbols(lib uintptr) error {
	var err error
	reg := func(fptr interface{}, name string) {
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

	return err
}
