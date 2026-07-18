package web

import (
	"io/fs"
	"testing"
)

func TestEmbeddedAssets(t *testing.T) {
	for _, name := range []string{"dist/index.html", "dist/assets/app.js", "dist/assets/app.css"} {
		if _, err := fs.ReadFile(Dist, name); err != nil {
			t.Fatalf("embedded asset %s: %v", name, err)
		}
	}
}
