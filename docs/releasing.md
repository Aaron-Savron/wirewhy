# Releasing

1. Run `npm ci`, `npm run check`, and `npm run test:package`.
2. Update the version and changelog.
3. Run `npm pack --dry-run` and check the file list.
4. Install the tarball in a clean project. Check imports and the CLI.
5. Publish with `npm publish --access public` when the npm name and account are ready.

The package runs directly from JavaScript source. There is no compilation step and no runtime dependency to install. Types ship beside the source.

CI covers Node 20, 22, and 24 on Linux, macOS, and Windows. System-CA fixture tests run on supported Linux runtimes.
