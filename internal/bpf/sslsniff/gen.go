package sslsniff

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" -target amd64 -type probe_SSL_data_t sslsniff ../../../bpf/sslsniff.bpf.c -- -I../../../vmlinux/x86
