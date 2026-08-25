package wardenassets

import (
	"embed"
	"io/fs"
)

//go:embed public
var embedded embed.FS

func PublicFS() fs.FS {
	sub, err := fs.Sub(embedded, "public")
	if err != nil {
		panic(err)
	}
	return sub
}
