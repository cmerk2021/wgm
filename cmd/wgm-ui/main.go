// Command wgm-ui is the unprivileged desktop client for wgmd.
package main

import (
	"flag"
	"fmt"
	"os"

	"fyne.io/fyne/v2/app"

	"github.com/cmerk2021/wgm/internal/api"
	"github.com/cmerk2021/wgm/ui"
)

var version = "dev"

func main() {
	socket := flag.String("socket", api.DefaultSocketPath, "wgmd control socket")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("wgm-ui", version)
		return
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "wgm-ui must not run as root. Run it as your normal user; membership in the 'wgm' group grants access to the daemon.")
		os.Exit(1)
	}
	fa := app.NewWithID("io.github.cmerk2021.wgm")
	ui.New(fa, *socket).ShowAndRun()
}
