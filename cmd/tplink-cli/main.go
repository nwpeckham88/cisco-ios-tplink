package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/nwpeckham88/cisco-ios-tplink/tplink"
)

const maxDecodeBackupSize = 2 << 20

func usageText() string {
	return "usage: tplink-cli <host> [--user USER] [--password PASSWORD] [--config-file FILE] | tplink-cli --decode-backup FILE"
}

func main() {
	var user string
	var password string
	var passwordStdin bool
	var passwordFile string
	var passwordEnv string
	var configFile string
	var decodeBackupFile string
	var host string

	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.StringVar(&user, "user", "admin", "Username (default: admin)")
	fs.StringVar(&user, "u", "admin", "Username (shorthand)")
	fs.StringVar(&password, "password", "", "Password override")
	fs.StringVar(&password, "p", "", "Password override (shorthand)")
	fs.BoolVar(&passwordStdin, "password-stdin", false, "Read password from stdin")
	fs.StringVar(&passwordFile, "password-file", "", "Read password from file")
	fs.StringVar(&passwordEnv, "password-env", "TPLINK_PASSWORD", "Environment variable for password")
	fs.StringVar(&configFile, "config-file", "", "Run commands from file and exit")
	fs.StringVar(&decodeBackupFile, "decode-backup", "", "Decode a binary TP-Link backup file and exit")

	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		host = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if decodeBackupFile != "" {
		f, err := os.Open(decodeBackupFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read backup file %q: %v\n", decodeBackupFile, err)
			os.Exit(1)
		}
		defer f.Close()

		data, err := io.ReadAll(io.LimitReader(f, maxDecodeBackupSize+1))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read backup file %q: %v\n", decodeBackupFile, err)
			os.Exit(1)
		}
		if len(data) > maxDecodeBackupSize {
			fmt.Fprintf(os.Stderr, "backup file %q exceeds max decode size (%d bytes)\n", decodeBackupFile, maxDecodeBackupSize)
			os.Exit(1)
		}
		decoded, err := tplink.DecodeBackupConfig(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to decode backup %q: %v\n", decodeBackupFile, err)
			os.Exit(1)
		}
		fmt.Print(tplink.FormatDecodedBackup(decoded))
		return
	}

	if host == "" {
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, usageText())
			os.Exit(2)
		}
		host = fs.Arg(0)
	}

	if host == "" {
		fmt.Fprintln(os.Stderr, usageText())
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
	cli := tplink.NewCLI(client, hostname)
	if configFile != "" {
		if err := cli.RunScriptFile(configFile); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		return
	}
	fmt.Println("In interactive terminals: press ? for immediate help and Tab for completion. Type 'exit' to disconnect.")
	fmt.Println()
	if err := cli.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
