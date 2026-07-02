-- wrk script: POST through the TokenFuse gateway (managed run, huge budget so the
-- request is never blocked — we're measuring overhead, not enforcement).
wrk.method = "POST"
wrk.body = '{"model":"m","max_tokens":50}'
wrk.headers["Content-Type"] = "application/json"
wrk.headers["x-fuse-run-id"] = "bench"
wrk.headers["x-fuse-budget-usd"] = "1000000000"
