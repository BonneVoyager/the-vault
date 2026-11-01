# Random mode: a seeded interleaving of CLI operations on A and B with partial deliveries (dropped,
# vault.bin only, delayed, forced conflict copies of all four shapes). Every operation is planned by
# model.py from the model state and the random numbers drawn HERE, in the parent shell ($RANDOM
# inside $(...) would be reseeded, so a seed would not replay). After each full exchange round both
# devices must match the model (titles, favorites, tags, icons, fields, attachment bytes) and each
# other, byte for byte in vault.bin. The operation log is $LAB/oplog; --selfcheck replays a seed
# twice and diffs the logs.

random_run() { # random_run SEED STEPS [LABNAME]
  local seed="$1" steps="$2" step=0 r1 r2 r3 r4 r5 r6 line k desc
  RANDOM="$seed"
  lab_begin "${3:-random-$seed}"
  : >"$LAB/oplog"
  m_init
  new_vault A
  mop add A i0
  mdeliver A B
  while [ "$step" -lt "$steps" ] && [ -z "$SCN_FAILS" ]; do
    step=$((step + 1))
    r1=$RANDOM r2=$RANDOM r3=$RANDOM r4=$RANDOM r5=$RANDOM r6=$RANDOM
    line="$(m plan "$step" "$r1" "$r2" "$r3" "$r4" "$r5" "$r6")"
    echo "$step $line" >>"$LAB/oplog"
    set -- $line
    k="$1"
    desc="$line"
    case "$k" in
      noop) continue ;;
      deliver) mdeliver "$2" "$3" "$4" ;;
      round)
        mexchange "$2" "$3"
        mcheck --bytes A B
        ;;
      *) exec_op "$@" ;;
    esac
    if [ -n "$SCN_FAILS" ]; then
      SCN_FAILS="$SCN_FAILS
     first divergence: seed=$seed step=$step op='$desc' (replay: --random --seed $seed --steps $steps; lab: $LAB)"
      return 1
    fi
  done
  [ -z "$SCN_FAILS" ] || return 1
  echo "final round" >>"$LAB/oplog"
  mexchange A B
  mcheck --bytes A B
  if [ -n "$SCN_FAILS" ]; then
    SCN_FAILS="$SCN_FAILS
     first divergence: seed=$seed at the final round (replay: --random --seed $seed --steps $steps; lab: $LAB)"
    return 1
  fi
  return 0
}

# Two runs of one seed must plan identical operations.
selfcheck_replay() { # selfcheck_replay SEED STEPS
  local l1 l2
  local f1
  random_run "$1" "$2" "replay-1"
  l1="$LAB/oplog"
  f1="$SCN_FAILS" # lab_begin clears the failure state: keep run 1's
  random_run "$1" "$2" "replay-2"
  l2="$LAB/oplog"
  if [ -n "$f1" ]; then SCN_FAILS="run 1 failed:$f1$SCN_FAILS"; fi
  [ -z "$SCN_FAILS" ] || return 0
  [ -s "$l1" ] || fail "empty operation log"
  cmp -s "$l1" "$l2" || fail "seed $1 did not replay: $(diff "$l1" "$l2" | head -4)"
}
