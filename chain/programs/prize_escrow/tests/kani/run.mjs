#!/usr/bin/env node
// Verifies the Kani proofs in this directory inside Docker: the host never gets Kani's toolchain
// (.cosmos/rules/host-runtime.mdc). It builds agent-fun-kani:0.68.0 from ./Dockerfile, mounts the
// chain workspace read-only (so Cargo.lock here is used as committed: cargo cannot rewrite it),
// keeps cargo's registry and Kani's target in named Docker volumes, and runs each harness in its
// own `cargo kani --exact --harness <name>`, so every harness gets its own log and wall time.
//
//   node chain/programs/prize_escrow/tests/kani/run.mjs [filter ...] [--jobs N] [--solver S]
//                                                       [--timeout MINUTES]
//   node chain/programs/prize_escrow/tests/kani/run.mjs --relock
//   node chain/programs/prize_escrow/tests/kani/run.mjs --mutants
//
// --mutants runs mutants.sh here in one container: each mutant a copy of the program with one
// seeded bug, which the harness meant to catch it must fail. Its table goes to
// <worktree>/.tmp/kani/mutants.out, each mutant's Kani log to mutant.<name>.log there; exit 0 when
// every mutant was caught (VERIFICATION:- FAILED).
//
// --relock rewrites Cargo.lock here from chain/Cargo.lock, pruned to this crate's graph by the cargo
// of chain/rust-toolchain.toml's channel in the image (it keeps the versions chain/Cargo.lock pins
// and drops the rest), for when the program's dependencies change: the read-only mount refuses any
// other lockfile write. The image installs that channel (Dockerfile's CHAIN_TOOLCHAIN, read from
// the toolchain file at every run), so a toolchain bump rebuilds one layer.
//
// A filter selects the harnesses whose module::name contains it (all of them by default). Logs go
// to <worktree>/.tmp/kani/<module>.<harness>.log, the image build's to image-build.log, and the
// table of results (result, checks, covers satisfied, Kani's verification time, wall time) to
// summary.md and summary.json there. Exit 0 when every selected harness verified with all its
// covers satisfied.
//
// Docker Desktop gives its VM a fixed memory (8 GB here), shared with every other container: the
// larger merkle trees take a few GB each, and overlapping runs got Kani killed by the VM's OOM
// killer (OUT OF MEMORY below), so --jobs defaults to 1.

import { spawn, spawnSync } from 'node:child_process'
import { closeSync, copyFileSync, mkdirSync, openSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const IMAGE = 'agent-fun-kani:0.68.0'
const here = dirname(fileURLToPath(import.meta.url))
const chain = resolve(here, '../../../..')
const worktree = resolve(chain, '..')
const logs = join(worktree, '.tmp', 'kani')
const inContainer = '/src/chain/programs/prize_escrow/tests/kani'

const args = process.argv.slice(2)
const filters = []
let jobs = 1
let solver = null
let timeoutMinutes = null
let relock = false
let mutants = false
for (let i = 0; i < args.length; i++) {
  const arg = args[i]
  if (arg === '--relock') relock = true
  else if (arg === '--mutants') mutants = true
  else if (arg === '--jobs') jobs = Number(args[++i])
  else if (arg === '--solver') solver = args[++i]
  else if (arg === '--timeout') timeoutMinutes = Number(args[++i])
  else if (arg.startsWith('--')) throw new Error(`unknown option ${arg}`)
  else filters.push(arg)
}
if (!(jobs >= 1)) throw new Error('--jobs takes a positive number')

/** Every #[kani::proof] in src/, as module::name. */
function harnesses() {
  const found = []
  for (const file of readdirSync(join(here, 'src')).sort()) {
    if (!file.endsWith('.rs') || file === 'lib.rs') continue
    const module = file.slice(0, -3)
    const source = readFileSync(join(here, 'src', file), 'utf8')
    for (const m of source.matchAll(/#\[kani::proof\](?:\s*#\[[^\]]*\])*\s*fn (\w+)/g)) {
      found.push(`${module}::${m[1]}`)
    }
  }
  return found
}

function dockerRun(name, kaniArgs, logFile) {
  const fd = openSync(logFile, 'w')
  const child = spawn(
    'docker',
    [
      // A cap of its own, so an out-of-memory CBMC is killed alone and named in the VM's log
      // rather than taking another container with it.
      'run', '--rm', '--name', name, '--memory', '6g',
      '-v', `${chain}:/src/chain:ro`,
      '-v', 'agent-fun-kani-registry:/usr/local/cargo/registry',
      '-v', 'agent-fun-kani-target:/target',
      '-e', 'CARGO_TARGET_DIR=/target',
      '-w', inContainer,
      IMAGE, 'cargo', 'kani', ...kaniArgs,
    ],
    { stdio: ['ignore', fd, fd] },
  )
  let timer = null
  let timedOut = false
  if (timeoutMinutes) {
    timer = setTimeout(() => {
      timedOut = true
      spawnSync('docker', ['kill', name], { stdio: 'ignore' })
    }, timeoutMinutes * 60_000)
  }
  return new Promise((done) => {
    child.on('exit', (code) => {
      if (timer) clearTimeout(timer)
      closeSync(fd)
      done({ code, timedOut })
    })
  })
}

/** What one harness's log says: its result, its checks and Kani's verification time. */
function parse(log) {
  const result = log.match(/VERIFICATION:- (\w+)/)?.[1] ?? null
  const checks = log.match(/\*\* (\d+) of (\d+) failed/)
  const covers = log.match(/\*\* (\d+) of (\d+) cover properties satisfied/)
  const time = log.match(/Verification Time: ([\d.]+)s/)?.[1]
  const failed = [...log.matchAll(/^Check \d+: .*\n\s+- Status: FAILURE\n\s+- Description: "([^"]*)"/gm)].map((m) => m[1])
  return {
    result,
    failedChecks: checks ? Number(checks[1]) : null,
    checks: checks ? Number(checks[2]) : null,
    verificationSeconds: time ? Number(time) : null,
    coversSatisfied: covers ? Number(covers[1]) : null,
    covers: covers ? Number(covers[2]) : null,
    cbmcFailed: /CBMC failed/.test(log),
    // CBMC reports its own allocation failure; a kill by the VM's OOM killer leaves the driver
    // without an exit code.
    outOfMemory: /run out of memory|No exit code\?/.test(log),
    failed,
  }
}

mkdirSync(logs, { recursive: true })
const selected = harnesses().filter((h) => filters.length === 0 || filters.some((f) => h.includes(f)))
if (selected.length === 0) throw new Error(`no harness matches ${filters.join(', ')}`)

const buildLog = join(logs, 'image-build.log')
const buildFd = openSync(buildLog, 'w')
// The channel chain/rust-toolchain.toml pins: `cargo` under chain/ resolves to it in the container.
const toolchain = readFileSync(join(chain, 'rust-toolchain.toml'), 'utf8').match(/^channel\s*=\s*"([^"]+)"/m)?.[1]
if (!toolchain) throw new Error(`no channel in ${join(chain, 'rust-toolchain.toml')}`)
const built = spawnSync(
  'docker',
  ['build', '-t', IMAGE, '--build-arg', `CHAIN_TOOLCHAIN=${toolchain}`, '-f', join(here, 'Dockerfile'), here],
  { stdio: ['ignore', buildFd, buildFd] },
)
closeSync(buildFd)
if (built.status !== 0) {
  console.error(`docker build failed (exit ${built.status}): ${buildLog}`)
  process.exit(1)
}

if (mutants) {
  // The worktree's .tmp/kani/ is mutants.sh's /logs; its stdout is the table.
  const out = join(logs, 'mutants.out')
  const outFd = openSync(out, 'w')
  const ran = spawnSync(
    'docker',
    [
      'run', '--rm', '--name', `agent-fun-kani-${process.pid}-mutants`, '--memory', '6g',
      '-v', `${chain}:/src/chain:ro`,
      '-v', `${logs}:/logs`,
      '-v', 'agent-fun-kani-registry:/usr/local/cargo/registry',
      '-v', 'agent-fun-kani-target:/target',
      '-e', 'CARGO_TARGET_DIR=/target',
      IMAGE, 'sh', `${inContainer}/mutants.sh`,
    ],
    { stdio: ['ignore', outFd, 'inherit'] },
  )
  closeSync(outFd)
  const lines = readFileSync(out, 'utf8').split('\n').filter((line) => line.startsWith('MUTANT '))
  const missed = lines.filter((line) => !line.includes('VERIFICATION:- FAILED'))
  console.log([...lines, '', `${lines.length - missed.length} of ${lines.length} mutants caught: ${out}`].join('\n'))
  process.exit(ran.status === 0 && lines.length > 0 && missed.length === 0 ? 0 : 1)
}

if (relock) {
  copyFileSync(join(chain, 'Cargo.lock'), join(here, 'Cargo.lock'))
  const pruned = spawnSync(
    'docker',
    [
      'run', '--rm',
      '-v', `${chain}:/src/chain:ro`,
      '-v', `${here}:${inContainer}`,
      '-v', 'agent-fun-kani-registry:/usr/local/cargo/registry',
      '-w', inContainer,
      IMAGE, 'cargo', `+${toolchain}`, 'metadata', '--format-version', '1',
    ],
    { stdio: ['ignore', 'ignore', 'inherit'] },
  )
  console.log(pruned.status === 0 ? `relocked ${join(here, 'Cargo.lock')}` : 'relock failed')
  process.exit(pruned.status === 0 ? 0 : 1)
}

const results = []
const queue = [...selected]
const startedAt = new Date().toISOString()
const row = (r) =>
  `| ${r.harness} | ${r.verdict} | ${r.checks ?? '-'} | ${r.coversSatisfied ?? '-'}/${r.covers ?? '-'} | ${r.verificationSeconds?.toFixed(1) ?? '-'} | ${r.wallSeconds.toFixed(1)} | ${r.startedAt} |`
const table = (rs) => [
  '| harness | result | checks | covers | verification s | wall s | run started |',
  '|---|---|---|---|---|---|---|',
  ...rs.map(row),
]

// summary.json keeps each harness's latest run, so a filtered run updates only its own rows; it is
// rewritten after every harness, so a run cut short keeps what it finished.
const summaryJson = join(logs, 'summary.json')
function writeSummary() {
  let previous = []
  try {
    previous = JSON.parse(readFileSync(summaryJson, 'utf8')).results ?? []
  } catch {}
  const latest = new Map(previous.map((r) => [r.harness, r]))
  for (const r of results) latest.set(r.harness, r)
  const all = harnesses().filter((h) => latest.has(h)).map((h) => latest.get(h))
  writeFileSync(summaryJson, `${JSON.stringify({ image: IMAGE, results: all }, null, 2)}\n`)
  writeFileSync(join(logs, 'summary.md'), [`Kani 0.68.0 in ${IMAGE}, each harness's latest run`, '', ...table(all), ''].join('\n'))
}
async function worker(slot) {
  for (let harness = queue.shift(); harness; harness = queue.shift()) {
    const logFile = join(logs, `${harness.replace('::', '.')}.log`)
    const kaniArgs = ['--exact', '--harness', harness, ...(solver ? ['--solver', solver] : [])]
    const started = Date.now()
    console.log(`[${slot}] ${harness} ...`)
    const { code, timedOut } = await dockerRun(`agent-fun-kani-${process.pid}-${slot}`, kaniArgs, logFile)
    const wallSeconds = (Date.now() - started) / 1000
    const parsed = parse(readFileSync(logFile, 'utf8'))
    // Reach checks are off (Cargo.toml), so a harness whose assumptions exclude every path would
    // pass vacuously: its covers must all be satisfied.
    const vacuous = parsed.covers === null || parsed.coversSatisfied !== parsed.covers
    const verdict = timedOut
      ? 'TIMEOUT'
      : parsed.result === 'SUCCESSFUL' && code === 0
        ? vacuous
          ? 'VACUOUS'
          : 'SUCCESSFUL'
        : parsed.outOfMemory
          ? 'OUT OF MEMORY'
          : 'FAILED'
    results.push({ harness, verdict, exit: code, wallSeconds, ...parsed, log: logFile, startedAt, solver })
    writeSummary()
    console.log(`[${slot}] ${harness}: ${verdict} (${parsed.verificationSeconds ?? '-'} s verification, ${wallSeconds.toFixed(1)} s wall)`)
  }
}
await Promise.all(Array.from({ length: Math.min(jobs, selected.length) }, (_, i) => worker(i)))
results.sort((a, b) => selected.indexOf(a.harness) - selected.indexOf(b.harness))

console.log(['', `This run (started ${startedAt}${solver ? `, solver ${solver}` : ''}):`, '', ...table(results)].join('\n'))
process.exit(results.every((r) => r.verdict === 'SUCCESSFUL') ? 0 : 1)
