# infrastructure/workers

Security workers run outside the API process and (in later phases) launch tool adapters in isolated containers with CPU/memory/time/network limits. This phase ships only the queue foundation and a harmless placeholder job.
