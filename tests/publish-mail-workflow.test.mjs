import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflow = readFileSync(
  new URL("../.github/workflows/publish-webmail.yml", import.meta.url),
  "utf8",
);

function sourceIndexPolicy() {
  const match = workflow.match(/source_index_policy='\n([\s\S]*?)\n\s+'/);
  assert.ok(match, "missing source index policy");
  return match[1];
}

function sourceIndexAccepted(index, platform = "linux/amd64") {
  return (
    spawnSync("jq", ["-e", "--arg", "platform", platform, sourceIndexPolicy()], {
      input: JSON.stringify(index),
      encoding: "utf8",
    }).status === 0
  );
}

test("mail publisher uses native architecture runners and assembles one immutable index", () => {
  assert.match(workflow, /runner: ubuntu-24\.04\n\s+platform: linux\/amd64\n\s+arch: amd64/);
  assert.match(workflow, /runner: ubuntu-24\.04-arm\n\s+platform: linux\/arm64\n\s+arch: arm64/);
  assert.match(workflow, /runs-on: \$\{\{ matrix\.runner \}\}/);
  assert.match(workflow, /platforms: \$\{\{ matrix\.platform \}\}/);
  assert.match(workflow, /name=ghcr\.io\/\$\{GITHUB_REPOSITORY_OWNER,,\}\/openship-\$IMAGE_NAME/);
  assert.match(
    workflow,
    /outputs: type=image,name=\$\{\{ steps\.repository\.outputs\.name \}\},push-by-digest=true,name-canonical=true,push=true/,
  );
  assert.doesNotMatch(workflow, /name=ghcr\.io\/\$\{\{ github\.repository_owner \}\}/);
  assert.match(workflow, /push-by-digest=true,name-canonical=true,push=true/);
  assert.match(workflow, /steps\.build\.outputs\.digest/);
  assert.match(workflow, /--format "\{\{json \.Image\}\}"/);
  assert.doesNotMatch(workflow, /index \.Image/);
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

test("source index policy rejects duplicate runnable manifests", () => {
  const runnable = {
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    digest: `sha256:${"a".repeat(64)}`,
    platform: { os: "linux", architecture: "amd64" },
  };
  const attestation = {
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    digest: `sha256:${"b".repeat(64)}`,
    platform: { os: "unknown", architecture: "unknown" },
    annotations: {
      "vnd.docker.reference.digest": runnable.digest,
      "vnd.docker.reference.type": "attestation-manifest",
    },
  };
  const valid = {
    mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [runnable, attestation],
  };

  assert.equal(sourceIndexAccepted(valid), true);
  assert.equal(
    sourceIndexAccepted({
      ...valid,
      manifests: [runnable, { ...runnable, digest: `sha256:${"c".repeat(64)}` }, attestation],
    }),
    false,
  );
});
