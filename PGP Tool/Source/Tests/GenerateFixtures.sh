#!/usr/bin/env bash
set -euo pipefail

# makes a bunch of throwaway gpg keys + messages and bakes them into Fixtures.h
# so the tests don't need gpg installed. needs gpg on PATH to run though (git bash has it)
# tip: run with TMPDIR set to something short, gpg-agent dies if the socket path is too long
OUTPUT="$(cd "$(dirname "$0")" && pwd)/Fixtures.h"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fx.XXXXXX")"
trap 'gpgconf --homedir "$WORK/home" --kill all >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

export GNUPGHOME="$WORK/home"
mkdir "$GNUPGHOME"
chmod 700 "$GNUPGHOME" 2>/dev/null || true
GPG="gpg --batch --yes --quiet --pinentry-mode loopback"

# alice = curve25519 w/ passphrase, bob = rsa w/ passphrase, carol = no passphrase, dave = signing only (should get refused)
$GPG --passphrase 'alice pass' --quick-gen-key 'Alice <alice@example.com>' future-default default never
$GPG --passphrase 'bob pass' --quick-gen-key 'Bob <bob@example.com>' rsa3072 sign,cert never
BOB=$(gpg --list-keys --with-colons bob@example.com | awk -F: '/^fpr/ { print $10; exit }')
$GPG --passphrase 'bob pass' --quick-add-key "$BOB" rsa3072 encr never
$GPG --passphrase '' --quick-gen-key 'Carol <carol@example.com>' future-default default never
$GPG --passphrase '' --quick-gen-key 'Dave <dave@example.com>' rsa3072 sign,cert never

cd "$WORK"
printf 'Hello world, \xc3\xbcn\xc3\xafc\xc3\xb8d\xc3\xa9 \xe2\x9c\x93\nSecond line\n' > sample.txt
for i in $(seq 1 60); do printf 'Line %02d of the chunked OCB fixture message.\n' "$i"; done > medium.txt

$GPG -a --export alice@example.com > alice.pub
$GPG -a --passphrase 'alice pass' --export-secret-keys alice@example.com > alice.sec
$GPG -a --export bob@example.com > bob.pub
$GPG -a --passphrase 'bob pass' --export-secret-keys bob@example.com > bob.sec
$GPG -a --export carol@example.com > carol.pub
$GPG -a --passphrase '' --export-secret-keys carol@example.com > carol.sec
$GPG -a --export dave@example.com > dave.pub

# one message per weird case we care about: zlib, chunked OCB, signed, zip, hidden recipient, none, bzip2
$GPG -a -r alice@example.com -o alice-default.asc -e sample.txt
$GPG -a -r alice@example.com --force-ocb --chunk-size 6 --compress-algo none -o alice-ocb.asc -e medium.txt
$GPG -a --passphrase 'alice pass' -s --local-user alice@example.com -r alice@example.com -o alice-signed.asc -e sample.txt
$GPG -a -r bob@example.com --compress-algo zip -o bob-zip.asc -e sample.txt
$GPG -a -r bob@example.com --throw-keyids -o bob-hidden.asc -e sample.txt
$GPG -a -r carol@example.com --compress-algo none -o carol-plain.asc -e sample.txt
$GPG -a -r carol@example.com --compress-algo bzip2 -o carol-bzip2.asc -e sample.txt

$GPG --dearmor < carol-plain.asc > carol-plain.bin
# flip one bit 10 bytes from the end so it lands in the MDC hash, not the header
OFFSET=$(( $(wc -c < carol-plain.bin) - 10 ))
BYTE=$(od -An -tu1 -j "$OFFSET" -N1 carol-plain.bin | tr -d ' ')
cp carol-plain.bin carol-tampered.bin
printf "$(printf '\\%03o' $(( BYTE ^ 1 )))" | dd of=carol-tampered.bin bs=1 seek="$OFFSET" conv=notrunc status=none
$GPG --enarmor < carol-tampered.bin | sed 's/ARMORED FILE/MESSAGE/' > carol-tampered.asc

emit() {
    printf '\n    inline constexpr char %s[] = R"PGP(' "$1"
    cat "$2"
    printf ')PGP";\n'
}

{
    printf '#pragma once\n\nnamespace Fixtures\n{\n'
    printf '    inline constexpr char AlicePassphrase[] = "alice pass";\n'
    printf '    inline constexpr char BobPassphrase[] = "bob pass";\n'
    emit SampleText sample.txt
    emit MediumText medium.txt
    emit AlicePublic alice.pub
    emit AliceSecret alice.sec
    emit BobPublic bob.pub
    emit BobSecret bob.sec
    emit CarolPublic carol.pub
    emit CarolSecret carol.sec
    emit DavePublic dave.pub
    emit AliceDefault alice-default.asc
    emit AliceOcb alice-ocb.asc
    emit AliceSigned alice-signed.asc
    emit BobZip bob-zip.asc
    emit BobHidden bob-hidden.asc
    emit CarolPlain carol-plain.asc
    emit CarolBzip2 carol-bzip2.asc
    emit CarolTampered carol-tampered.asc
    printf '}\n'
} > "$OUTPUT"

echo "Wrote $OUTPUT"
