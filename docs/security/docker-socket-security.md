# Docker Socket Security (Prompt 13 §30/§106)

The Docker socket is root-equivalent on a host. ZeroSweep's rule is
absolute: **no ZeroSweep component mounts or connects to a Docker
socket** — not the web app, not the API, not general workers, not
source workers, not container-analysis workers.

- `docker-compose.yml` contains no `docker.sock` mount (a test asserts
  this and fails the build if one appears).
- No adapter plan can express a socket path, a `docker run`, or a
  privileged container flag; adapter plans are executable + argument
  arrays produced in code, and a test sweeps every cloud-native plan
  for forbidden tokens.
- Image content reaches the `CONTAINER_ANALYSIS` worker as a cached,
  content-addressed artifact through platform storage — never through
  a daemon.
- Docker Bench for Security does not use the socket through ZeroSweep:
  it runs on a dedicated `PRIVILEGED_HOST` worker against an explicitly
  approved host assessment, executor-gated on the
  `PRIVILEGED_HOST_ASSESSMENT` capability. General workers are refused
  with `UNAVAILABLE_FOR_WORKER` and the stage degrades honestly.
