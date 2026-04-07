package asherah_test

import (
	"fmt"
	"os"
	"strings"

	asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

func Example() {
	os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))

	err := asherah.Setup(asherah.Config{
		ServiceName: "example-service",
		ProductID:   "example-product",
		Metastore:   "memory",
		KMS:         "static",
	})
	if err != nil {
		fmt.Println("setup error:", err)
		return
	}
	defer asherah.Shutdown()

	ct, err := asherah.EncryptString("my-partition", "hello world")
	if err != nil {
		fmt.Println("encrypt error:", err)
		return
	}

	pt, err := asherah.DecryptString("my-partition", ct)
	if err != nil {
		fmt.Println("decrypt error:", err)
		return
	}

	fmt.Println("decrypted:", pt)
}
