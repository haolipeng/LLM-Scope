package stdiocap

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" -target amd64 -type stdiocap_event_t stdiocap ../../../bpf/stdiocap.bpf.c -- -I../../../vmlinux/x86
