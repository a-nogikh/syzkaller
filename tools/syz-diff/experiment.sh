#!/bin/bash

run_experiment() {
  COMMIT="$1"
  CONFIG="$2"
  TITLE="$3"

  echo "--------"
  date
  echo "COMMIT: $COMMIT"
  echo "TITLE: $TITLE"

  echo "Building the base kernel"
  (
    cd ~/linux-base
    git clean -fxfd
    git reset --hard "$COMMIT"
    git revert "$COMMIT" --no-edit
    wget -O '.config' 'https://raw.githubusercontent.com/google/syzkaller/master/dashboard/config/linux/upstream-apparmor-kasan.config'
    make CC=clang LD=ld.lld olddefconfig
    make CC=clang LD=ld.lld -j32
  ) >/dev/null 2>&1

  echo "Building the patched kernel"
  (
    cd ~/linux-patched
    git clean -fxfd
    git reset --hard "$COMMIT"
    wget -O '.config' 'https://raw.githubusercontent.com/google/syzkaller/master/dashboard/config/linux/upstream-apparmor-kasan.config'
    make CC=clang LD=ld.lld olddefconfig
    make CC=clang LD=ld.lld -j32
  ) >/dev/null 2>&1
  
  WORKDIR="experiment_0609/$(date +"%Y-%m-%d_%H-%M-%S")_$COMMIT"
  mkdir -p "$WORKDIR"
  echo "COMMIT: $COMMIT" > "$WORKDIR/description.txt"
  echo "TITLE: $TITLE" >> "$WORKDIR/description.txt"
  echo "WORKDIR: $WORKDIR"

  FULL_WORKDIR=$(realpath "$WORKDIR")
  (
    cd ~/linux-base
    git show "$COMMIT" > "$FULL_WORKDIR/patch.diff"
  )
  cp base.cfg "$WORKDIR/"
  cp "$CONFIG" "$WORKDIR/patched.cfg"

  (
    cd "$WORKDIR"
    timeout 3h ../../syz-diff -base base.cfg -new patched.cfg -patch patch.diff -kernel ~/linux-patched 2>&1 | tee "log.log" | grep "patched-only"
  )
}

#run_experiment d25a92ccae6b patched_net.cfg "WARNING: refcount bug in inet_create"
#run_experiment d18d3f0a24fc patched_net.cfg "KASAN: slab-use-after-free Read in l2tp_tunnel_del_work"
#run_experiment 181a42edddf5 patched_net.cfg "WARNING in hci_conn_del"
#run_experiment 401cb7dae8130 patched_net.cfg "stack segment fault in cpu_map_redirect"
#run_experiment 186b1ea73ad8 patched_net.cfg "kernel BUG in dev_gro_receive"
run_experiment af0cb3fa3f9e patched_net.cfg "KASAN: slab-use-after-free Read in htab_map_alloc"
#run_experiment f7a8b10bfd61 patched_net.cfg "WARNING in rdev_scan"

#run_experiment 275dca4630c1 patched_fs.cfg "KASAN: slab-use-after-free Read in kill_f2fs_super"
#run_experiment 16aac5ad1fa9 patched_fs.cfg "general protection fault in ovl_encode_real_fh"

#run_experiment 948dbafc15da patched_net.cfg "KASAN: global-out-of-bounds Read in __nla_validate_parse"
#run_experiment c3718936ec47 patched_net.cfg "WARNING: suspicious RCU usage in in6_dump_addrs"

#run_experiment 94a69db2367e patched_fs.cfg "possible deadlock in xfs_ilock"
#run_experiment b5357cb268c4 patched_fs.cfg "KASAN: slab-out-of-bounds Read in btrfs_qgroup_inherit"
#run_experiment 310ee0902b8d patched_fs.cfg "WARNING in ext4_iomap_begin"
#run_experiment 744a56389f73 patched_fs.cfg "WARNING in __fortify_report"
#run_experiment c3defd99d58c patched_fs.cfg "divide error in ext4_mb_regular_allocator"
#run_experiment 11a347fb6cef patched_fs.cfg "kernel BUG in iov_iter_revert"
#run_experiment 0586d0a89e77 patched_fs.cfg "kernel BUG in btrfs_folio_end_all_writers"
