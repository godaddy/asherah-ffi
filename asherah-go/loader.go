package asherah

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	loadOnce  sync.Once
	loadErr   error
	loadError string // stores load-time error message
)

func ensureLoaded() error {
	loadOnce.Do(func() {
		loadErr = loadLibrary()
	})
	return loadErr
}

func loadLibrary() error {
	paths := candidateLibraryPaths()
	if len(paths) == 0 {
		return fmt.Errorf("asherah-go: no candidate native library paths found")
	}

	var attempts []string
	for _, path := range paths {
		lib, err := openLibrary(path)
		if err != nil {
			attempts = append(attempts, fmt.Sprintf("%s (%v)", path, err))
			continue
		}
		if err := loadSymbols(lib); err != nil {
			attempts = append(attempts, fmt.Sprintf("%s (%v)", path, err))
			continue
		}
		loadError = ""
		return nil
	}

	loadError = fmt.Sprintf("asherah-go: unable to load native library; attempted: %s", strings.Join(attempts, "; "))
	return fmt.Errorf("%s", loadError)
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func candidateLibraryPaths() []string {
	names := libraryBasenames()
	var paths []string

	envPath := strings.TrimSpace(os.Getenv("ASHERAH_GO_NATIVE"))
	if envPath != "" {
		if info, err := os.Stat(envPath); err == nil && info.IsDir() {
			for _, name := range names {
				candidate := filepath.Join(envPath, name)
				paths = append(paths, candidate)
			}
		} else {
			paths = append(paths, envPath)
		}
	}

	// Check current working directory (default install-native output location).
	if cwd, err := os.Getwd(); err == nil {
		for _, name := range names {
			candidate := filepath.Join(cwd, name)
			if fileExists(candidate) {
				paths = append(paths, candidate)
			}
		}
	}

	if cargoDir := strings.TrimSpace(os.Getenv("CARGO_TARGET_DIR")); cargoDir != "" {
		for _, name := range names {
			paths = append(paths, filepath.Join(cargoDir, "debug", name))
			paths = append(paths, filepath.Join(cargoDir, "release", name))
		}
	}

	moduleDir := currentModuleDir()
	repoRoot := filepath.Dir(moduleDir)
	candidates := []string{
		filepath.Join(repoRoot, "target", "debug"),
		filepath.Join(repoRoot, "target", "release"),
		filepath.Join(repoRoot, "asherah-ffi", "target", "debug"),
		filepath.Join(repoRoot, "asherah-ffi", "target", "release"),
	}

	for _, dir := range candidates {
		for _, name := range names {
			candidate := filepath.Join(dir, name)
			if fileExists(candidate) {
				paths = append(paths, candidate)
			}
		}
	}

	// Check user cache directory (populated by install-native command).
	if cacheDir, err := os.UserCacheDir(); err == nil {
		cacheLibDir := filepath.Join(cacheDir, "asherah-go")
		for _, name := range names {
			candidate := filepath.Join(cacheLibDir, name)
			if fileExists(candidate) {
				paths = append(paths, candidate)
			}
		}
	}

	// Allow library names without path for system-installed copies.
	paths = append(paths, names...)

	return dedupeStrings(paths)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

var (
	moduleDirOnce sync.Once
	moduleDirPath string
)

func currentModuleDir() string {
	moduleDirOnce.Do(func() {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			moduleDirPath = "."
			return
		}
		moduleDirPath = filepath.Dir(file)
	})
	return moduleDirPath
}

func libraryBasenames() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{"asherah_ffi.dll"}
	case "darwin":
		return []string{"libasherah_ffi.dylib"}
	default:
		return []string{"libasherah_ffi.so"}
	}
}
