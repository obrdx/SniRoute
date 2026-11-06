// Command sniroute is the single binary for SniRoute.
//
// Usage:
//
//	sniroute                 interactive menu
//	sniroute client|server   role menus and subcommands
//	sniroute genkey
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/nyktios/sniroute/internal/auth"
	"github.com/nyktios/sniroute/internal/client"
	"github.com/nyktios/sniroute/internal/server"
	"github.com/nyktios/sniroute/internal/tui"
	buildversion "github.com/nyktios/sniroute/internal/version"
)

const usage = `SniRoute - egress routing and access-restriction probe

Usage:
  sniroute                          interactive menu (client / server)
  sniroute client                   client menu (enroll, domains, settings, run a test)
  sniroute client enroll [flags]    register this machine non-interactively
  sniroute client probe  [flags]    run a test non-interactively and print the report
  sniroute client reports [list|show ID|export ID|asn ID|flush]   task history, reports, re-send queued records
  sniroute reports ...              same as: client reports
  sniroute server                   server management menu
  sniroute server run [flags]       run the service in the foreground (for systemd)
  sniroute server start|stop|restart|status [-config path]
  sniroute genkey                   print a new random key
  sniroute version
`

const version = buildversion.Application

func main() {
	if len(os.Args) < 2 {
		if err := topMenu(); err != nil {
			fmt.Fprintln(os.Stderr, "sniroute:", err)
			os.Exit(1)
		}
		return
	}
	switch os.Args[1] {
	case "server":
		if err := runServer(os.Args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return
			}
			tui.New(os.Stdin, os.Stderr).Styled("danger", fmt.Sprint("server: ", err))
			os.Exit(1)
		}
	case "client":
		if err := runClient(os.Args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return
			}
			tui.New(os.Stdin, os.Stderr).Styled("danger", fmt.Sprint("client: ", err))
			os.Exit(1)
		}
	case "reports":
		// `sniroute reports` is the client's history (the machine under test).
		if err := clientReports(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "reports:", err)
			os.Exit(1)
		}
	case "genkey":
		fmt.Println(auth.GenerateKey())
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func topMenu() error {
	ui := tui.New(os.Stdin, os.Stdout)
	for {
		key, err := ui.Menu("SniRoute 服务商出口分流探测", nil, []tui.Item{
			tui.Opt("1", "客户端：发起测试"), tui.Opt("2", "服务端：配置与管理"), tui.Opt("0", "退出"),
		})
		if err != nil {
			return quitOnCancel(err)
		}
		switch key {
		case "1":
			err = clientMenu(client.DefaultConfigPath())
		case "2":
			err = serverMenu(server.DefaultConfigPath())
		case "0":
			return nil
		}
		if err != nil {
			return err
		}
	}
}
