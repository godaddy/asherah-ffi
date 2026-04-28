// Disable test parallelization across the whole assembly. Multiple test
// classes (RoundTripTests, HookTests) touch global Asherah state — the
// shared factory singleton, the global metrics gate, and the registered
// log/metrics hooks. Running them in parallel races those globals.
[assembly: Xunit.CollectionBehavior(DisableTestParallelization = true)]
