package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// tailFile follows path like `tail -F`: starts at the end, survives
// logrotate (rename + create) and copytruncate.
func tailFile(ctx context.Context, path string, out chan<- string) {
	var (
		f       *os.File
		r       *bufio.Reader
		partial string
		first   = true
	)
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	for ctx.Err() == nil {
		if f == nil {
			var err error
			if f, err = os.Open(path); err != nil {
				if first {
					log.Printf("tail %s: %v (waiting for it)", path, err)
				}
				first = false
				sleep(ctx, 5*time.Second)
				continue
			}
			if first {
				_, _ = f.Seek(0, io.SeekEnd) // only new lines; a rotated-in file is read from the start
			}
			first = false
			r = bufio.NewReader(f)
		}

		chunk, err := r.ReadString('\n')
		partial += chunk
		if err == nil {
			select {
			case out <- strings.TrimRight(partial, "\r\n"):
			case <-ctx.Done():
				return
			}
			partial = ""
			continue
		}

		// EOF: everything written so far is read, so now check for rotation.
		cur, err1 := f.Stat()
		disk, err2 := os.Stat(path)
		switch {
		case err1 != nil || err2 != nil || !os.SameFile(cur, disk):
			f.Close()
			f, partial = nil, ""
		case disk.Size() < offset(f):
			_, _ = f.Seek(0, io.SeekStart) // truncated in place
			r.Reset(f)
			partial = ""
		default:
			sleep(ctx, time.Second)
		}
	}
}

func offset(f *os.File) int64 {
	pos, _ := f.Seek(0, io.SeekCurrent)
	return pos
}

// tailJournal streams new messages of the given systemd units. Shelling out to
// journalctl keeps the binary static (sdjournal needs cgo).
func tailJournal(ctx context.Context, units []string, out chan<- string) {
	args := []string{"--follow", "--lines=0", "--output=cat", "--no-pager"}
	for _, u := range units {
		args = append(args, "--unit="+u)
	}

	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, "journalctl", args...)
		stdout, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err == nil {
			sc := bufio.NewScanner(stdout)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				select {
				case out <- sc.Text():
				case <-ctx.Done():
				}
			}
			err = cmd.Wait()
		}
		if ctx.Err() != nil {
			return
		}
		// ponytail: lines logged while restarting are missed; use --cursor if that matters.
		log.Printf("journalctl %v exited: %v; restarting in 5s", units, err)
		sleep(ctx, 5*time.Second)
	}
}

// sleep waits d or until ctx is done; false means ctx is done.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
