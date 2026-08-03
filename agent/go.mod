module github.com/ALIRAZA47/ratline/agent

// Pinned to the patch rather than the minor. The build claims to be
// reproducible and byte-identical across machines (RL-M2-001), and two
// different 1.26.x toolchains do not always produce identical binaries. The
// `toolchain` line means a machine with an older patch fetches this one rather
// than failing, so the pin costs nothing.
go 1.26.5

// NO REQUIRE BLOCK, AND THAT IS THE POINT.
//
// The brief (§6.7) prefers the standard library, and this module is the one
// place where the preference becomes a hard property: `agent/internal/build`
// has a test that fails if a single external module is ever required. The agent
// runs as an unprivileged process on somebody else's host, next to a root
// helper it is designed not to be trusted by, and every dependency it gains is
// a supply-chain path onto that host.
//
// Adding one is allowed. Adding one silently is not: the test names the file to
// edit, and §6.7 wants the one-line justification in the commit body.
