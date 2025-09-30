package asherah

/*
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "unsafe"
)

var (
    loadOnce sync.Once
    loadErr  error
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
        return errors.New("asherah-go: no candidate native library paths found")
    }

    var attempts []string
    for _, path := range paths {
        cpath := C.CString(path)
        rc := C.asherah_go_load(cpath)
        C.free(unsafe.Pointer(cpath))
        if rc == 0 {
            return nil
        }
        attempts = append(attempts, fmt.Sprintf("%s (%s)", path, lastErrorMessage()))
    }

    return fmt.Errorf("asherah-go: unable to load native library; attempted: %s", strings.Join(attempts, "; "))
}

func lastErrorMessage() string {
    msg := C.asherah_go_last_error()
    if msg == nil {
        return "unknown error"
    }
    return C.GoString(msg)
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
