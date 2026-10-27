# Issue tracker: GitHub

Optional settings for agent skills, such as [mattpocock/skills](https://github.com/mattpocock/skills), that read them. If you don't use such skills, ignore this file.

Issues and specs for this repo live as GitHub issues. Where a skill or tool refers to an issue tracker, ticket or issue, it means a GitHub issue in this repo. Use the `gh` CLI:

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --json number,title,body,labels,comments`.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Make an issue a sub-issue of a parent**: `gh issue create --parent <parent> ...`, or `gh issue edit <parent> --add-sub-issue <child>` afterwards (`gh` 2.94+). Without sub-issues, put `Part of #<parent>` at the top of the child body.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`. Work normally closes through a PR with `Fixes #<number>`.

Labelling, assigning and closing need triage rights on the repo. GitHub shares one number space across issues and PRs, so resolve a bare `#42` with `gh pr view 42` and fall back to `gh issue view 42`.
