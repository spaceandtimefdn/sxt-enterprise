# Space and Time Enterprise

A deployable SQL database that returns a cryptographic proof of correctness with every query
result, verifiable independently of the server that produced it.

Space and Time Enterprise, from MakeInfinite Labs, is the first verifiable database. Every
query returns a zero-knowledge proof binding its result to the submitted SQL and to a
commitment to the tables it read. Checked against a commitment the client already trusts, that
proof establishes that the result is the output of that SQL over the committed data.

It builds on [Proof of SQL](https://github.com/spaceandtimefdn/sxt-proof-of-sql), packaged as a
database server that runs on an ordinary laptop or server. The workflow is the familiar one:
create a table, insert data, run a query. The only difference is that the query returns a proof
along with its result, which you check locally with the CLI or a verifier library. Proving
happens on that same machine, so the database does not require a blockchain, GPU, or network of
nodes to commit the data, and private enterprise data stays on infrastructure you control.
Typical uses are auditing, compliance, financial records, and onchain applications that depend
on offchain data. In each case, the party consuming a result can verify it without receiving
the underlying data and without trusting the server that produced it.

## How it works

The server is a standalone SQL database: create a table, insert rows, run a query. It is a
single process, with no cluster to join, no network to coordinate with,
and no external service in the path of a query. Query results can also be cryptographically
verified after the fact by a client that has the corresponding trusted commitments.

A commitment is a short cryptographic fingerprint of a table's contents. Each table has one at
`<data>/<table>/table.commit`, and every insert extends it to cover the new rows. Altering or
dropping a committed row changes the fingerprint.

The proof shows that the result is the output of the submitted SQL over the committed data.
Checking it requires only the SQL, proof, and commitments; the database, rows, and prover setup
are not needed. An auditor can verify the result offline, on their own laptop.

The operator runs `serve`, holds the data, and produces proofs. The verifier checks proofs
against commitments obtained independently, so verification does not depend on trusting the
server that produced the result.

Proving uses a public parameter set from the Perpetual Powers of Tau ceremony, which `serve`
and `setup` download and cache automatically. Verification derives its key from a single
constant compiled into the binary, so it needs no download and no network access.

## Install

```sh
cargo install --path .
```

Or build the [Dockerfile](Dockerfile). The same binary runs the server and the verification
CLI; an auditor installs it and uses `verify`.

## Quick start

Start the server, define a table, insert rows, then run a query and verify its proof.

```sh
sxt-enterprise serve &

curl -s localhost:8080/tables -H 'content-type: application/json' -d '{
  "table": "db.products",
  "columns": [{"name": "id", "type": "BIGINT"}, {"name": "name", "type": "VARCHAR"}, {"name": "price", "type": "INT"}]}'

curl -s localhost:8080/tables/db.products/rows -H 'content-type: application/json' -d '{
  "rows": [{"id": 1, "name": "widget", "price": 999}]}'

curl -s localhost:8080/query -H 'content-type: application/json' -d '{
  "sql": "SELECT name FROM db.products WHERE price > 500"}' > response.json

sxt-enterprise verify --sql "SELECT name FROM db.products WHERE price > 500" \
  --response response.json
```

The last command verifies the saved response against the commitments on disk and prints the
verified rows. A failed proof exits non-zero.

## CLI

| Command | Flags | Does |
| --- | --- | --- |
| `serve` | `--data <dir>` (default `~/.sxt-enterprise`) `--listen <addr>` (default `0.0.0.0:8080`) `--rows <n>` (default `1024`) | Serves the HTTP API. |
| `verify` | `--sql <query>` `--response <file>` `--commitments <dir>` (default `~/.sxt-enterprise`) | Verifies a saved `POST /query` response. |
| `setup` | `--rows <n>` `--out <file>` (default `setup.bin`) | Pre-generates the prover's setup file, for warming a deployment's cache ahead of time. |

`serve` is the long-running process; `verify` and `setup` are one-shot commands. `verify` reads
only the response file and a directory of commitments.

`--rows N` resolves to `N.next_power_of_two()` rows of proving capacity; querying beyond the
resolved capacity fails outright rather than silently truncating. `serve` caches its resolved
setup at `<data>/setup.bin`, downloading it on first use. `setup` downloads the same file ahead
of time so a deployment can start serving immediately. Size the capacity above the row count
you expect to reach, since raising it later means fetching a larger parameter set.

## HTTP API

The API is deliberately small: define a table, append rows, ask a question. Inserts are
append-only; there is no update or delete.

| Route | Body | Does |
| --- | --- | --- |
| `POST /tables` | `{"table", "columns": [{"name", "type"}]}` | Creates an empty table. Supported types: `BOOLEAN`, `TINYINT`, `SMALLINT`, `INT`, `BIGINT`, `VARCHAR`. |
| `POST /tables/{table}/rows` | `{"rows": [{...}]}` | Appends rows, each a JSON object keyed by column name. |
| `POST /query` | `{"sql"}` | Proves `sql` against the table's current data; see below for the response shape. |
| `GET /tables` | — | Lists every table. |
| `GET /tables/{table}` | — | The table's columns, row count, and commitment. |
| `GET /health` | — | Liveness check. |

A `POST /query` response carries the proof and the commitments it was proved against, so the
whole JSON blob can go to an auditor on its own:

```json
{
  "rows": [{"name": "widget"}],
  "proof": "<base64>",
  "tables": {"db.products": {"commitment": "<base64>", "num_rows": 1}}
}
```

## Verifying a response

`verify` checks against the commitments pinned on disk at `--commitments <dir>` (default
`~/.sxt-enterprise`, the same `<table>/table.commit` files `serve` writes), not the ones a
response happens to report. If that directory doesn't exist, it falls back to the response's own
commitments, printing a warning that it's doing so.

A proof is only useful if the verifier already trusts the commitments. If the server supplies
both, it can commit to fabricated data and prove a query over it, and the proof still checks
out. Pin commitments from a deployment you trust, publish them to an auditor in advance, record
them in a compliance system, or anchor them onchain.

A commitment represents a specific state of the table. A response proved before an insert will
not verify against a commitments directory that has since grown, because the fingerprint no
longer matches the data the proof was built over. That fails with an error and a non-zero exit
status, the same as a bad proof. Keep a copy of the commitments taken alongside a response if
you intend to re-verify it later.

## What the proof guarantees

A verified proof establishes that the returned rows are the output of the submitted SQL over
the data covered by the commitments used to check it. Everything else is outside its scope.

The HTTP API ships with no authentication or authorization, so put it behind your own access
control before exposing it beyond localhost. Results come back in the clear; confidentiality
comes from the data staying on infrastructure you control. Nothing in a proof establishes that
the commitments used to check it are the right ones, which remains the verifier's
responsibility. Commitments cover contents, not timestamps or ordering against an external
clock, so pair them with trusted timestamping if you need it. Queries must be a single
statement over the supported column types, within the deployment's configured proving capacity.
