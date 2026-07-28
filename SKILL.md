# The greenlight skill has moved

It now lives at [`skills/greenlight/SKILL.md`](skills/greenlight/SKILL.md).

Claude Code discovers a plugin's skills under `skills/<name>/SKILL.md`. While
this file sat at the repo root, `/plugin install greenlight` installed a plugin
that provided nothing.

This pointer stays because people look for `SKILL.md` here (see
[#3](https://github.com/RevylAI/greenlight/issues/3)).

## Install

```bash
# In Claude Code
/plugin marketplace add RevylAI/greenlight
/plugin install greenlight
```

Or copy it into a project by hand:

```bash
mkdir -p .claude/skills
cp skills/greenlight/SKILL.md .claude/skills/greenlight.md
```
