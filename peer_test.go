package awgctrl

import (
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
)

func Test_parseTimespec(t *testing.T) {
	var zero [sizeofTimespec64]byte

	tests := []struct {
		name string
		b    []byte
		t    time.Time
		ok   bool
	}{
		{
			name: "bad",
			b:    []byte{0xff},
		},
		{
			name: "timespec32",
			b: (*(*[sizeofTimespec32]byte)(unsafe.Pointer(&timespec32{
				Sec:  1,
				Nsec: 2,
			})))[:],
			t:  time.Unix(1, 2),
			ok: true,
		},
		{
			name: "timespec64",
			b: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
				Sec:  2,
				Nsec: 1,
			})))[:],
			t:  time.Unix(2, 1),
			ok: true,
		},
		{
			name: "zero seconds",
			b: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
				Nsec: 1,
			})))[:],
			t:  time.Unix(0, 1),
			ok: true,
		},
		{
			name: "zero nanoseconds",
			b: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
				Sec: 1,
			})))[:],
			t:  time.Unix(1, 0),
			ok: true,
		},
		{
			name: "zero both",
			b:    zero[:],
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got time.Time
			err := parseTimespec(&got)(tt.b)
			if tt.ok && err != nil {
				t.Fatalf("failed to parse timespec: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				t.Logf("err: %v", err)
				return
			}

			if diff := cmp.Diff(tt.t, got); diff != "" {
				t.Fatalf("unexpected time (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_timespec32MemoryLayout(t *testing.T) {
	// Assume unix.Timespec has 32-bit integers exclusively.
	if a := runtime.GOARCH; a != "386" {
		t.Skipf("skipping, architecture %q not handled in 32-bit only test", a)
	}

	// Verify unix.Timespec and timespec32 have an identical memory layout.
	uts := unix.Timespec{
		Sec:  1,
		Nsec: 2,
	}

	if diff := cmp.Diff(sizeofTimespec32, int(unsafe.Sizeof(unix.Timespec{}))); diff != "" {
		t.Fatalf("unexpected timespec size (-want +got):\n%s", diff)
	}

	ts := *(*timespec32)(unsafe.Pointer(&uts))

	if diff := cmp.Diff(uts.Sec, ts.Sec); diff != "" {
		t.Fatalf("unexpected timespec seconds (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(uts.Nsec, ts.Nsec); diff != "" {
		t.Fatalf("unexpected timespec nanoseconds (-want +got):\n%s", diff)
	}
}

func Test_timespec64MemoryLayout(t *testing.T) {
	// Assume unix.Timespec has 64-bit integers exclusively.
	if a := runtime.GOARCH; a != "amd64" {
		t.Skipf("skipping, architecture %q not handled in 64-bit only test", a)
	}

	// Verify unix.Timespec and timespec64 have an identical memory layout.
	uts := unix.Timespec{
		Sec:  1,
		Nsec: 2,
	}

	if diff := cmp.Diff(sizeofTimespec64, int(unsafe.Sizeof(unix.Timespec{}))); diff != "" {
		t.Fatalf("unexpected timespec size (-want +got):\n%s", diff)
	}

	ts := *(*timespec64)(unsafe.Pointer(&uts))

	if diff := cmp.Diff(uts.Sec, ts.Sec); diff != "" {
		t.Fatalf("unexpected timespec seconds (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(uts.Nsec, ts.Nsec); diff != "" {
		t.Fatalf("unexpected timespec nanoseconds (-want +got):\n%s", diff)
	}
}
