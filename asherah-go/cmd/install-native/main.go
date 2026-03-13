// install-native downloads the prebuilt Asherah native library for the current platform.
//
// Usage:
//
//	go run github.com/godaddy/asherah-go/cmd/install-native@latest
//	go run github.com/godaddy/asherah-go/cmd/install-native@latest --version v0.6.24
//	go run github.com/godaddy/asherah-go/cmd/install-native@latest --output /usr/local/lib
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const defaultRepo = "godaddy/asherah-ffi"

func main() {
	version := flag.String("version", "", "Release version (e.g., v0.6.24). Defaults to latest.")
	output := flag.String("output", "", "Output directory. Defaults to user cache dir.")
	repo := flag.String("repo", defaultRepo, "GitHub repository (owner/name).")
	flag.Parse()

	if *version == "" {
		v, err := fetchLatestVersion(*repo)
		if err != nil {
			fatalf("failed to determine latest version: %v", err)
		}
		*version = v
		fmt.Printf("Latest release: %s\n", *version)
	}

	assetName, err := assetNameForPlatform(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		fatalf("%v", err)
	}

	destDir := *output
	if destDir == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			fatalf("unable to determine cache dir: %v", err)
		}
		destDir = filepath.Join(cacheDir, "asherah-go")
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		fatalf("mkdir %s: %v", destDir, err)
	}

	localName := localLibraryName(runtime.GOOS)
	destFile := filepath.Join(destDir, localName)

	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", *repo, *version, assetName)
	fmt.Printf("Downloading %s ...\n", url)

	if err := downloadFile(url, destFile); err != nil {
		fatalf("download failed: %v", err)
	}

	if runtime.GOOS != "windows" {
		_ = os.Chmod(destFile, 0o755)
	}

	// Verify checksum
	checksumURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/SHA256SUMS", *repo, *version)
	if err := verifyChecksum(checksumURL, assetName, destFile); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: checksum verification skipped: %v\n", err)
	} else {
		fmt.Println("SHA256 checksum verified.")
	}

	fmt.Printf("\nInstalled: %s\n", destFile)
	fmt.Printf("\nTo use, set the environment variable:\n")
	fmt.Printf("  export ASHERAH_GO_NATIVE=%s\n", destDir)
}

func assetNameForPlatform(goos, goarch string) (string, error) {
	arch := ""
	switch goarch {
	case "amd64":
		arch = "x64"
	case "arm64":
		arch = "arm64"
	default:
		return "", fmt.Errorf("unsupported architecture: %s", goarch)
	}

	ext := ""
	switch goos {
	case "linux":
		ext = "so"
	case "darwin":
		ext = "dylib"
	case "windows":
		ext = "dll"
	default:
		return "", fmt.Errorf("unsupported OS: %s", goos)
	}

	return fmt.Sprintf("libasherah-%s.%s", arch, ext), nil
}

func localLibraryName(goos string) string {
	switch goos {
	case "windows":
		return "asherah_ffi.dll"
	case "darwin":
		return "libasherah_ffi.dylib"
	default:
		return "libasherah_ffi.so"
	}
}

func fetchLatestVersion(repo string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	// Use GITHUB_TOKEN if available for rate limiting
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", fmt.Errorf("no tag_name in response")
	}
	return release.TagName, nil
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}

	_, err = io.Copy(f, resp.Body)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}

	return os.Rename(tmp, dest)
}

func verifyChecksum(checksumURL, assetName, localFile string) error {
	resp, err := http.Get(checksumURL)
	if err != nil {
		return fmt.Errorf("fetch checksums: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("checksums not available (HTTP %d)", resp.StatusCode)
	}

	// Parse SHA256SUMS format: "<hash>  <filename>"
	var expectedHash string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == assetName {
			expectedHash = parts[0]
			break
		}
	}
	if expectedHash == "" {
		return fmt.Errorf("no checksum found for %s", assetName)
	}

	f, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actualHash := hex.EncodeToString(h.Sum(nil))

	if actualHash != expectedHash {
		os.Remove(localFile)
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	return nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
