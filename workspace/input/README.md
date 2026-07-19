# Input workspace

Place files for Open WebUI tools to inspect or parse in this directory.

This directory is mounted read-only at `/workspace/input` inside the Open WebUI and
CloudBeaver containers. CloudBeaver can use it for SQLite and other file-backed data
sources. Its contents are ignored by Git.
