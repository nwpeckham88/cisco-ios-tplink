package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/nwpeckham88/cisco-ios-tplink/tplink"
)

func main() {
	var user string
	var password string
	var passwordStdin bool
	var passwordFile string
	var passwordEnv string
	var host string

	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.StringVar(&user, "user", "admin", "Username (default: admin)")
	fs.StringVar(&user, "u", "admin", "Username (shorthand)")
	fs.StringVar(&password, "password", "", "Password override")
	fs.StringVar(&password, "p", "", "Password override (shorthand)")
	fs.BoolVar(&passwordStdin, "password-stdin", false, "Read password from stdin")
	fs.StringVar(&passwordFile, "password-file", "", "Read password from file")
	fs.StringVar(&passwordEnv, "password-env", "TPLINK_PASSWORD", "Environment variable for password")

	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		host = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if host == "" {
		if fs.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "usage: tplink-cli <host> [--user USER] [--password PASSWORD]\n")
			os.Exit(2)
		}
		host = fs.Arg(0)
	}

	if host == "" {
		fmt.Fprintf(os.Stderr, "usage: tplink-cli <host> [--user USER] [--password PASSWORD]\n")
		os.Exit(2)
	}

	resolvedPassword, err := tplink.ResolvePassword(password, passwordStdin, passwordFile, passwordEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}

	fmt.Printf("Connecting to %s... ", host)
	client, err := tplink.NewClient(host, tplink.WithUsername(user), tplink.WithPassword(resolvedPassword))
	if err != nil {
		fmt.Println("FAILED")
		fmt.Println(err)
		os.Exit(1)
	}
	if err := client.Login(); err != nil {
		fmt.Println("FAILED")
		fmt.Println(err)
		os.Exit(1)
	}
	defer client.Logout()

	info, err := client.GetSystemInfo()
	if err != nil {
		fmt.Println("FAILED")
		fmt.Println(err)
		os.Exit(1)
	}
	hostname := regexp.MustCompile(`[^A-Za-z0-9_-]`).ReplaceAllString(info.Description, "-")
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		hostname = "switch"
	}

	fmt.Println("OK")
	fmt.Printf("  %s  |  FW: %s  |  IP: %s\n\n", info.Description, info.Firmware, info.IP)
	fmt.Println("Type ? for help. Type 'exit' to disconnect.")
	fmt.Println()

	cli := tplink.NewCLI(client, hostname)
	if err := cli.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
