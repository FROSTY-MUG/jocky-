## Summary

## Which STEP does this belong to?

## Files changed

## Verification gates run (paste raw output)

## Does this add a denylisted primitive? (yes/no — if yes, stop)

## Does this weaken consent enforcement? (yes/no — if yes, stop)

## Checklist
- [ ] cargo test -p jockyc passes
- [ ] cargo clippy -p jockyc -- -D warnings passes
- [ ] All stdlib scripts still parse
- [ ] Denylist tests still pass
- [ ] No new unsafe code (or justified in the description)
