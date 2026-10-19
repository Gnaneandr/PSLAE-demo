"""PSLAE research-demonstration layer. Calls the REAL protocol code (src/ = the audited reconstruction)
and never modifies it. Protocol code is instrumented at run time only (monkey-patched wrappers that record sizes, never secret values)."""
