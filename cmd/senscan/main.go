package main

import (
	"fmt"
	"os"

	"github.com/jyufu/sensitive-info-scan/internal/app"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	if err := app.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
