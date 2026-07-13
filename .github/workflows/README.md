# .github/workflows

GitHub Actions pipelines for this service.

- **`ci.yml`** — on push/PR to `main`: mandatory full-workspace formatting,
  locked all-target/all-feature Clippy and tests, and a pinned `cargo-audit`.
  It checks out the sibling
  `fiducia-cloud/fiducia-interfaces` repo at the exact commit also pinned by the
  Dockerfile so the path-dependency crates
  (`../fiducia-interfaces/generated/...`) resolve reproducibly.
- **`deploy-test.yml`** — secret-gated rollout to the `fiducia-test` Kubernetes
  namespace (sets the deployment image to the commit-SHA tag). No-op when
  `KUBE_CONFIG_TEST` is absent; PROD deploys happen from the fiducia-monorepo,
  not here.
