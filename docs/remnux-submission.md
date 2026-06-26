# REMnux Submission Notes

## Current Status

Fit-review issue opened with REMnux before creating a pull request:

- https://github.com/REMnux/salt-states/issues/348

No REMnux pull request has been opened yet. This is intentional.

## REMnux Contribution Rules Checked

REMnux tool inclusion normally requires one of these paths:

- a tested Salt state in `REMnux/salt-states`;
- a Debian package proposal through `REMnux/distro`;
- a Docker image proposal through `REMnux/docker`.

The REMnux documentation recommends confirming with Lenny Zeltser that a tool
fits REMnux before creating Salt states, packaging files, or a pull request.

## AdversaryGraph Fit Constraints

AdversaryGraph should not be submitted directly as a normal REMnux Salt-state
tool until these points are resolved:

- it is a multi-container Docker Compose platform, not a single CLI utility;
- Malware Analysis mode is documented for v4 as a controlled lab workflow, but
  runtime execution remains gated to explicit isolated profiles;
- the repository uses a personal-use license, not a standard OSI license;
- REMnux may prefer a Docker-image, documentation-only, or no-inclusion path
  instead of installing the full platform into the distro.

## Next Step

Wait for maintainer guidance in the REMnux issue. If REMnux confirms the tool is
appropriate, prepare the integration path they request:

1. Docker image proposal in `REMnux/docker`;
2. Salt state in `REMnux/salt-states`;
3. documentation-only reference in `REMnux/docs`.
