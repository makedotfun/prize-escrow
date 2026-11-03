#!/bin/sh
# The mutation check of the Kani proofs in this directory: each mutant is a copy of the program
# with one seeded bug, and the harness meant to catch it must FAIL (VERIFICATION:- FAILED). It runs
# inside agent-fun-kani:0.68.0, never on the host:
#
#   node chain/programs/prize_escrow/tests/kani/run.mjs --mutants
#
# run.mjs builds the image, mounts chain/ read-only at /src/chain and the worktree's .tmp/kani/ at
# /logs, and runs this script there: one line per mutant on stdout (run.mjs keeps it as
# .tmp/kani/mutants.out), each mutant's Kani log at .tmp/kani/mutant.<name>.log. The copies live in
# the container (/w), so the worktree's program is never touched. A mutant whose pattern is gone
# from the program says so rather than passing.
set -u
run() {
  name=$1; file=$2; from=$3; to=$4; harness=$5
  rm -rf /w && mkdir -p /w/chain/programs/prize_escrow/tests
  cp /src/chain/Cargo.toml /src/chain/rust-toolchain.toml /w/chain/
  cp -r /src/chain/programs/prize_escrow/Cargo.toml /src/chain/programs/prize_escrow/build.rs \
    /src/chain/programs/prize_escrow/src /w/chain/programs/prize_escrow/
  cp -r /src/chain/programs/prize_escrow/tests/kani /w/chain/programs/prize_escrow/tests/
  target=/w/chain/programs/prize_escrow/$file
  grep -qF -- "$from" "$target" || { echo "MUTANT $name: pattern not found"; return; }
  # A literal replace (the patterns hold `|`, `*`, `?` and brackets), of each line holding it.
  cp "$target" /tmp/unmutated
  FROM=$from TO=$to perl -pi -e 's/\Q$ENV{FROM}\E/$ENV{TO}/' "$target"
  cmp -s /tmp/unmutated "$target" && { echo "MUTANT $name: not applied"; return; }
  cd /w/chain/programs/prize_escrow/tests/kani
  start=$(date +%s)
  cargo kani --exact --harness "$harness" > "/logs/mutant.$name.log" 2>&1
  status=$?
  verdict=$(grep -o 'VERIFICATION:- [A-Z]*' "/logs/mutant.$name.log" | tail -1)
  failed=$(grep -A1 'Status: FAILURE' "/logs/mutant.$name.log" | grep -o 'Description: "[^"]*"' | head -1)
  echo "MUTANT $name -> $harness: exit $status, $verdict, $(( $(date +%s) - start )) s${failed:+, first failure $failed}"
}

# #771's four.
run accept-overfunding src/instructions/open_escrow.rs \
  'require!(grown == amount, EscrowError::Overfunded);' \
  'require!(grown >= amount, EscrowError::Overfunded);' \
  deposit::check_deposit_passes_exactly_the_amount
run unsorted-pair src/merkle.rs 'if a < b {' 'if true {' \
  merkle::a_pair_hashes_its_children_smaller_first
run leaf-without-escrow src/merkle.rs '        escrow.as_ref(),' '' \
  merkle::a_leaf_is_the_prefixed_hash_of_its_escrow_claimant_and_amount
run freeze-counted-twice src/config.rs \
  '.saturating_sub(escrow.frozen_secs_at(global_now))' \
  '.saturating_sub(escrow.frozen_secs_at(global_now)).saturating_sub(escrow.frozen_secs)' \
  clock::escrow_now_is_the_escrow_layer_over_the_global_clock

# #1089's, one per harness area it added for #981's helpers: the unbonded floor, the window,
# the panel floor and the alternative.
# The floor forgets the pending commits' bonds, so it reads them as rent.
run floor-without-commit-bonds src/state.rs \
  '            .and_then(|bonds| bonds.checked_add(self.commit_bond))' \
  '            .and_then(|bonds| bonds.checked_add(0))' \
  bonds::the_floor_is_the_balance_less_every_tracked_bond
# pay_bond ignores the floor it is handed, so a payout past the tracked bonds takes the rent.
run pay-past-the-floor src/instructions/settle.rs \
  '        .filter(|left| *left >= floor)' \
  '        .filter(|_| true)' \
  bonds::the_floor_lets_out_exactly_the_tracked_bonds
# settle's window opens one second late, so at challenge_deadline neither escalate nor settle acts.
run settle-a-second-late src/instructions/settle.rs \
  '        now >= escrow.challenge_deadline,' \
  '        now > escrow.challenge_deadline,' \
  window::the_window_is_over_for_escalate_exactly_when_settle_may_settle
# escalate's window ignores a pending commit's reveal grace: it binds a result settle waits on.
run window-ignores-the-grace src/state.rs \
  '        Ok(self.pending_commits == 0 || now >= self.reveal_deadline()?)' \
  '        Ok(true)' \
  window::the_window_is_over_for_escalate_exactly_when_settle_may_settle
# The panel floor is strict, so floor 0 refuses an empty panel and floor k a panel of k.
run panel-floor-strict src/config.rs \
  '            terms.regraders.len() >= usize::from(self.min_regraders),' \
  '            terms.regraders.len() > usize::from(self.min_regraders),' \
  panel::the_floor_refuses_exactly_the_panels_below_it_of_1
# set_min_regraders takes floor 0.
run floor-zero-written src/config.rs \
  '            (1..=MAX_REGRADERS).contains(&min_regraders),' \
  '            (0..=MAX_REGRADERS).contains(&min_regraders),' \
  panel::set_min_regraders_writes_only_a_floor_a_panel_can_meet
# clear_alternative zeroes the posted total instead of the alternative's.
run clear-wipes-the-posted-total src/state.rs \
  '        self.alt_total = 0;' \
  '        self.total = 0;' \
  alternative::clearing_an_alternative_forgets_it_and_nothing_else
# record_alternative leaves the alternative's total unwritten.
run record-without-the-total src/state.rs \
  '        self.alt_total = challenge.alt_total;' \
  '' \
  alternative::recording_an_alternative_writes_it_and_nothing_else
