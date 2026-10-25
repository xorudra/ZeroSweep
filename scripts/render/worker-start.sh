#!/usr/bin/env bash
# Render start script for the ZeroSweep worker.
# Render has no free background-worker tier, so the worker runs as a free
# web service: a tiny HTTP listener satisfies Render's port check while
# the real worker process runs in the foreground of this script.
set -e
cd "$(dirname "$0")/../.."
node -e "require('http').createServer((q,s)=>{s.writeHead(200,{'content-type':'text/plain'});s.end('zerosweep worker: running')}).listen(process.env.PORT || 10000)" &
exec node apps/worker/dist/index.js
