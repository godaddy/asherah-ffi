//go:build windows

package asherah

import (
	"fmt"
	"syscall"
)

func openLibrary(path string) (uintptr, error) {
	h, err := syscall.LoadLibrary(path)
	if err != nil {
		return 0, fmt.Errorf("LoadLibrary(%s): %w", path, err)
	}
	return uintptr(h), nil
}

func loadSymbols(lib uintptr) error {
	h := syscall.Handle(lib)

	lookup := func(name string) (uintptr, error) {
		proc, err := syscall.GetProcAddress(h, name)
		if err != nil {
			return 0, fmt.Errorf("GetProcAddress(%s): %w", name, err)
		}
		return proc, nil
	}

	type symEntry struct {
		fptr *uintptr
		name string
	}

	// On Windows, purego isn't available. We use raw syscall trampolines.
	// For now, just verify the symbols exist — the actual purego RegisterLibFunc
	// approach works cross-platform, but Windows needs syscall.NewLazyDLL instead.
	// TODO: implement Windows support with syscall.NewLazyDLL or purego Windows support.
	syms := []string{
		"asherah_factory_new_from_env",
		"asherah_factory_new_with_config",
		"asherah_factory_free",
		"asherah_factory_get_session",
		"asherah_session_free",
		"asherah_encrypt_to_json",
		"asherah_decrypt_from_json",
		"asherah_buffer_free",
		"asherah_last_error_message",
	}

	for _, name := range syms {
		if _, err := lookup(name); err != nil {
			return err
		}
	}

	return fmt.Errorf("asherah-go: Windows support not yet implemented for purego")
}
