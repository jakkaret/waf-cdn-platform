# nginx/ml-gate

Mounted read-only at `/etc/nginx/ml-gate/` in `waf-nginx` (docker-compose.yml).

`hosts.map` here is written by dashboard-backend (`services/ml_gate.py`) from
each origin's ML Protection setting and is not tracked in git. It lists only
the verified hosts of origins in enforce mode:

```
"shop.example.com" "enforce:88:95";
```

`default.conf.template` includes `/etc/nginx/ml-gate/*.map` into the
`$ml_gate` map. A host that is not listed, or a missing file, is log mode:
the gate (`nginx/njs/mlgate.js`) sends the request straight on without
calling ML. Do not edit the file by hand; change the setting on the origin's
ML Protection tab, and the backend rewrites the file within a minute.
