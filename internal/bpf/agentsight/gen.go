package agentsight

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" -target amd64 -type event -type probe_SSL_data_t -type stdiocap_event_t agentsight ../../../bpf/agentsight.bpf.c -- -I../../../vmlinux/x86
