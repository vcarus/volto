# The filter .github/workflows/fuzz.yml puts on the output of the targets it
# lists in WITHHELD. The log of a run is public, and for those targets a
# failing input can be a datagram that stops a deployed server.
#
# It prints only the lines whose form is known to carry no input: libFuzzer's
# progress and INFO lines, the sanitizer's report header and stack frames,
# Rust's panic location and backtrace frames, and cargo's build lines. Every
# other line is dropped and counted. A panic message is dropped with them,
# because the oracles of these targets print parts of the input in it.
#
# From libFuzzer's `MS:` line to the end, nothing is printed. After that line
# libFuzzer prints the input as hex, as text and as base64, and cargo-fuzz
# then prints it whole as `{:?}` under "Output of `std::fmt::Debug`:". The
# text form begins with bytes the input chose, so no later line is trusted by
# its form.
#
# tests/it_release_assets.rs runs this file over a transcript with each form.

done { next }
/^MS: / {
    done = 1
    print "(the failing input is withheld, with every line after this one)"
    next
}
/^#[0-9]+[ \t]/ ||
/^[ \t]+#[0-9]+ 0x/ ||
/^[ \t]+[0-9]+: / ||
/^[ \t]+at / ||
/^stack backtrace:$/ ||
/^thread .* panicked at [^ ]+:[0-9]+:[0-9]+:$/ ||
/^==[0-9]+==[ ]?ERROR: / ||
/^SUMMARY: / ||
/^INFO: / ||
/^NOTE: / ||
/^[ \t]+(Compiling|Finished|Running|Downloading|Downloaded) / { print; next }
{ dropped++ }
END { if (dropped) print "(" dropped " other lines withheld)" }
