package adapters

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var safeHost = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]+$`)

// validHost guards every value that reaches a subprocess argv (no shell is used).
func validHost(h string) error {
	if h == "" || strings.HasPrefix(h, "-") || !safeHost.MatchString(h) {
		return fmt.Errorf("refusing unsafe host value %q", h)
	}
	return nil
}

const maxOut = 8 << 20

type limitedBuf struct{ bytes.Buffer }

func (l *limitedBuf) Write(p []byte) (int, error) {
	if l.Len()+len(p) > maxOut {
		return len(p), nil
	}
	return l.Buffer.Write(p)
}

func runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (string, string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", "", fmt.Errorf("%s is not installed on this machine", name)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	killTree(cmd)                   // on timeout/cancel kill the whole process tree, not just the parent
	cmd.WaitDelay = 2 * time.Second // never wait forever on output pipes held open by orphaned children
	var so, se limitedBuf
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return so.String(), se.String(), fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return so.String(), se.String(), err
}

func have(name string) (bool, string) {
	if _, err := exec.LookPath(name); err != nil {
		return false, name + " binary not found in PATH"
	}
	return true, ""
}

// readImport reads an uploaded export with a hard size cap.
func readImport(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("no import file supplied")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<20+1))
	if len(b) > 64<<20 {
		return nil, errors.New("import file larger than 64 MB")
	}
	return b, err
}
