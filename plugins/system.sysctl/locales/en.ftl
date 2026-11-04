sysctl-off-title = A kernel security setting is below the reference
sysctl-off-summary = { $key } is { $current }; the reference value is { $want }.
sysctl-may-affect-ptrace = Attaching a debugger to an already running program (gdb, strace) stops working.
sysctl-may-affect-bpf = Programs that load eBPF without privileges stop working. IbexWall is not affected: it runs privileged.
sysctl-may-affect-kexec = Cannot be undone without a reboot: kexec loading stays disabled until then.
sysctl-may-affect-rp-filter = May break VPNs and machines with several network routes.
sysctl-may-affect-sysrq = The SysRq emergency keys stop working.
