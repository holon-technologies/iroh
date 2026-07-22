# Start the project sandbox, creating it from the committed kit when needed.
sbx:
    #!/usr/bin/env bash
    set -euo pipefail

    sandbox_name="iroh-dev"
    project_dir="{{ justfile_directory() }}"

    if sbx ls | awk 'NR > 1 { print $1 }' | grep -Fxq "${sandbox_name}"; then
        exec sbx run --name "${sandbox_name}"
    fi

    exec sbx run \
        --name "${sandbox_name}" \
        --cpus 4 \
        --memory 8g \
        --kit "${project_dir}/.docker/sandbox" \
        codex "${project_dir}"
