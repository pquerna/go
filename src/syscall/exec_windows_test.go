// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package syscall_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"internal/syscall/windows"
)

func TestRunAtLowIntegrity(t *testing.T) {
	cmd := wilHelperCommand(t, "print_wil")

	token, err := windows.GetIntegrityLevelToken(windows.SID_WIL_LOW)
	if err != nil {
		t.Fatal(err)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token: token,
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}

	if strings.TrimSpace(string(out)) != "low" {
		t.Fatalf("Child process did not run as low integrity level: %s", string(out))
	}
}

func wilHelperCommand(t *testing.T, s ...string) *exec.Cmd {
	cs := []string{"-test.run=TestRunAtLowIntegrityHelper", "--"}
	cs = append(cs, s...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

func TestRunAtLowIntegrityHelper(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		t.Skip("not helper process")
		return
	}

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "No command\n")
		os.Exit(2)
	}
	switch args[0] {
	case "print_wil":
		wil, err := windows.GetProcessIntegrityLevel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
			os.Exit(9)
		}
		fmt.Printf("%s\n", wil)
	}
	os.Exit(0)
}
