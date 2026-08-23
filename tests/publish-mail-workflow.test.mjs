import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflow = readFileSync(
  new URL("../.github/workflows/publish-webmail.yml", import.meta.url),
  "utf8",
);

test("mail publisher uses native architecture runners and assembles one immutable index", () => {
  assert.match(workflow, /runner: ubuntu-24\.04\n\s+platform: linux\/amd64\n\s+arch: amd64/);
  assert.match(workflow, /runner: ubuntu-24\.04-arm\n\s+platform: linux\/arm64\n\s+arch: arm64/);
  assert.match(workflow, /runs-on: \$\{\{ matrix\.runner \}\}/);
  assert.match(workflow, /platforms: \$\{\{ matrix\.platform \}\}/);
  assert.match(workflow, /push-by-digest=true,name-canonical=true,push=true/);
  assert.match(workflow, /steps\.build\.outputs\.digest/);
  assert.match(workflow, /actions\/upload-artifact@[0-9a-f]{40}/);
  assert.match(workflow, /actions\/download-artifact@[0-9a-f]{40}/);
  assert.match(workflow, /vnd\.docker\.reference\.type/);
  assert.match(workflow, /attestation-manifest/);
  assert.match(workflow, /immutable_index="\$repository@\$image_digest"/);
  assert.match(workflow, /imagetools create --dry-run/);
  assert.match(workflow, /expected_image_digest/);
  assert.match(workflow, /expected_descriptors/);
  assert.match(workflow, /actual_descriptors/);
  assert.doesNotMatch(workflow, /imagetools inspect "\$base" --raw/);
  assert.match(workflow, /docker buildx imagetools create/);
  assert.match(workflow, /openship-\$IMAGE_NAME:jtyid-\$SOURCE_SHA/);
  assert.match(workflow, /"\$repository@\$digest"/);
  assert.doesNotMatch(workflow, /jtyid-\$SOURCE_SHA-\$ARCH/);
  assert.doesNotMatch(workflow, /setup-qemu-action/);
});

test("every package-writing job retains the founder, main, and protected-environment gates", () => {
  for (const job of ["build-platform", "publish-index"]) {
    const start = workflow.indexOf(`  ${job}:`);
    assert.ok(start >= 0, `missing ${job}`);
    const next = job === "build-platform" ? workflow.indexOf("\n  publish-index:", start + 3) : -1;
    const body = workflow.slice(start, next < 0 ? undefined : next);
    assert.match(body, /github\.ref == 'refs\/heads\/main'/);
    assert.match(body, /github\.event\.repository\.full_name == 'Joka-Source\/openship'/);
    assert.match(body, /github\.actor_id == '94633662'/);
    assert.match(body, /github\.triggering_actor == 'TrueKrishna'/);
    assert.match(body, /environment: webmail-publish/);
  }
});
