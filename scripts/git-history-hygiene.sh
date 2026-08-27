#!/bin/sh
set -eu

git rev-list --objects --all | while read -r object path; do
  [ "$(git cat-file -t "$object")" = blob ] || continue
  size=$(git cat-file -s "$object")
  if [ "$size" -gt 20971520 ]; then
    echo "oversized historical blob: $path ($size bytes)" >&2
    exit 1
  fi
  case "$path" in
    *.exe|*.dll|*.so|*.dylib|*.a|*.o|*.class|*.jar|*.zip|*.tar|*.tar.gz)
      echo "binary/archive in Git history: $path" >&2
      exit 1
      ;;
  esac
  magic=$(git cat-file blob "$object" | od -An -tx1 -N4 | tr -d ' \n')
  case "$magic" in
    7f454c46|4d5a*|cafebabe|cffaedfe|feedfacf)
      echo "executable magic in Git history: $path" >&2
      exit 1
      ;;
  esac
done
