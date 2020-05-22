CC = clang

objects += src/afxdp_user.o

libbpf_static_objects += libbpf/src/staticobjs/bpf.o libbpf/src/staticobjs/btf.o libbpf/src/staticobjs/libbpf_errno.o libbpf/src/staticobjs/libbpf_probes.o
libbpf_static_objects += libbpf/src/staticobjs/libbpf.o libbpf/src/staticobjs/netlink.o libbpf/src/staticobjs/nlattr.o libbpf/src/staticobjs/str_error.o
libbpf_static_objects += libbpf/src/staticobjs/hashmap.o libbpf/src/staticobjs/bpf_prog_linfo.o libbpf/src/staticobjs/xsk.o

LDFLAGS += -lconfig -lpthread -lelf -lz

all: afxdp_loader afxdp_filter
afxdp_loader: libbpf $(objects)
	clang $(LDFLAGS) -o afxdp_loader $(libbpf_static_objects) $(objects)
afxdp_filter: src/afxdp_kern.o
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/afxdp_kern.c -o src/afxdp_kern.bc
	llc -march=bpf -filetype=obj src/afxdp_kern.bc -o src/afxdp_kern.o
libbpf:
	$(MAKE) -C libbpf/src
clean:
	$(MAKE) -C libbpf/src clean
	rm -f src/*.o src/*.bc
	rm -f afxdp_loader
.PHONY: libbpf all
.DEFAULT: all