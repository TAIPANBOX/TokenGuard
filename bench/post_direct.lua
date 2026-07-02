-- wrk script: POST straight to the mock upstream (baseline, no gateway).
wrk.method = "POST"
wrk.body = '{"model":"m","max_tokens":50}'
wrk.headers["Content-Type"] = "application/json"
