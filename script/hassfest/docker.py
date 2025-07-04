"""Generate and validate the dockerfile."""

from dataclasses import dataclass
from pathlib import Path

from homeassistant import core
from homeassistant.components.go2rtc.const import RECOMMENDED_VERSION as GO2RTC_VERSION
from homeassistant.const import Platform
from homeassistant.util import executor, thread
from script.gen_requirements_all import gather_recursive_requirements

from .model import Config, Integration
from .requirements import PACKAGE_REGEX, PIP_VERSION_RANGE_SEPARATOR

DOCKERFILE_TEMPLATE = r"""# Automatically generated by hassfest.
#
# To update, run python3 -m script.hassfest -p docker
ARG BUILD_FROM
FROM ${{BUILD_FROM}}

# Synchronize with homeassistant/core.py:async_stop
ENV \
    S6_SERVICES_GRACETIME={timeout} \
    UV_SYSTEM_PYTHON=true \
    UV_NO_CACHE=true

ARG QEMU_CPU

# Home Assistant S6-Overlay
COPY rootfs /

# Needs to be redefined inside the FROM statement to be set for RUN commands
ARG BUILD_ARCH
# Get go2rtc binary
RUN \
    case "${{BUILD_ARCH}}" in \
        "aarch64") go2rtc_suffix='arm64' ;; \
        "armhf") go2rtc_suffix='armv6' ;; \
        "armv7") go2rtc_suffix='arm' ;; \
        *) go2rtc_suffix=${{BUILD_ARCH}} ;; \
    esac \
    && curl -L https://github.com/AlexxIT/go2rtc/releases/download/v{go2rtc}/go2rtc_linux_${{go2rtc_suffix}} --output /bin/go2rtc \
    && chmod +x /bin/go2rtc \
    # Verify go2rtc can be executed
    && go2rtc --version

# Install uv
RUN pip3 install uv=={uv}

WORKDIR /usr/src

## Setup Home Assistant Core dependencies
COPY requirements.txt homeassistant/
COPY homeassistant/package_constraints.txt homeassistant/homeassistant/
RUN \
    uv pip install \
        --no-build \
        -r homeassistant/requirements.txt

COPY requirements_all.txt home_assistant_frontend-* home_assistant_intents-* homeassistant/
RUN \
    if ls homeassistant/home_assistant_*.whl 1> /dev/null 2>&1; then \
        uv pip install homeassistant/home_assistant_*.whl; \
    fi \
    && uv pip install \
        --no-build \
        -r homeassistant/requirements_all.txt

## Setup Home Assistant Core
COPY . homeassistant/
RUN \
    uv pip install \
        -e ./homeassistant \
    && python3 -m compileall \
        homeassistant/homeassistant

WORKDIR /config
"""

_HASSFEST_TEMPLATE = r"""# Automatically generated by hassfest.
#
# To update, run python3 -m script.hassfest -p docker
FROM python:3.13-alpine

ENV \
    UV_SYSTEM_PYTHON=true \
    UV_EXTRA_INDEX_URL="https://wheels.home-assistant.io/musllinux-index/"

SHELL ["/bin/sh", "-o", "pipefail", "-c"]
ENTRYPOINT ["/usr/src/homeassistant/script/hassfest/docker/entrypoint.sh"]
WORKDIR "/github/workspace"

COPY . /usr/src/homeassistant

# Uv is only needed during build
RUN --mount=from=ghcr.io/astral-sh/uv:{uv},source=/uv,target=/bin/uv \
    # Uv creates a lock file in /tmp
    --mount=type=tmpfs,target=/tmp \
    # Required for PyTurboJPEG
    apk add --no-cache libturbojpeg \
    && uv pip install \
        --no-build \
        --no-cache \
        -c /usr/src/homeassistant/homeassistant/package_constraints.txt \
        -r /usr/src/homeassistant/requirements.txt \
        stdlib-list==0.10.0 \
        pipdeptree=={pipdeptree} \
        tqdm=={tqdm} \
        ruff=={ruff} \
        {required_components_packages}

LABEL "name"="hassfest"
LABEL "maintainer"="Home Assistant <hello@home-assistant.io>"

LABEL "com.github.actions.name"="hassfest"
LABEL "com.github.actions.description"="Run hassfest to validate standalone integration repositories"
LABEL "com.github.actions.icon"="terminal"
LABEL "com.github.actions.color"="gray-dark"
"""


def _get_package_versions(file: Path, packages: set[str]) -> dict[str, str]:
    package_versions: dict[str, str] = {}
    with file.open(encoding="UTF-8") as fp:
        for _, line in enumerate(fp):
            if package_versions.keys() == packages:
                return package_versions

            if match := PACKAGE_REGEX.match(line):
                pkg, sep, version = match.groups()

                if pkg not in packages:
                    continue

                if sep != "==" or not version:
                    raise RuntimeError(
                        f'Requirement {pkg} need to be pinned "{pkg}==<version>".'
                    )

                for part in version.split(";", 1)[0].split(","):
                    version_part = PIP_VERSION_RANGE_SEPARATOR.match(part)
                    if version_part:
                        package_versions[pkg] = version_part.group(2)
                        break

    if package_versions.keys() == packages:
        return package_versions

    raise RuntimeError("At least one package was not found in the requirements file.")


@dataclass
class File:
    """File."""

    content: str
    path: Path


def _generate_hassfest_dockerimage(
    config: Config, timeout: int, package_versions: dict[str, str]
) -> File:
    packages = set()
    already_checked_domains = set()
    for platform in Platform:
        packages.update(
            gather_recursive_requirements(platform.value, already_checked_domains)
        )
    # Add go2rtc requirements as this file needs the go2rtc integration
    packages.update(gather_recursive_requirements("go2rtc", already_checked_domains))

    return File(
        _HASSFEST_TEMPLATE.format(
            timeout=timeout,
            required_components_packages=" \\\n        ".join(sorted(packages)),
            **package_versions,
        ),
        config.root / "script/hassfest/docker/Dockerfile",
    )


def _generate_files(config: Config) -> list[File]:
    timeout = (
        core.STOPPING_STAGE_SHUTDOWN_TIMEOUT
        + core.STOP_STAGE_SHUTDOWN_TIMEOUT
        + core.FINAL_WRITE_STAGE_SHUTDOWN_TIMEOUT
        + core.CLOSE_STAGE_SHUTDOWN_TIMEOUT
        + executor.EXECUTOR_SHUTDOWN_TIMEOUT
        + thread.THREADING_SHUTDOWN_TIMEOUT
        + 10
    ) * 1000

    package_versions = _get_package_versions(config.root / "requirements.txt", {"uv"})
    package_versions |= _get_package_versions(
        config.root / "requirements_test.txt", {"pipdeptree", "tqdm"}
    )
    package_versions |= _get_package_versions(
        config.root / "requirements_test_pre_commit.txt", {"ruff"}
    )

    return [
        File(
            DOCKERFILE_TEMPLATE.format(
                timeout=timeout,
                **package_versions,
                go2rtc=GO2RTC_VERSION,
            ),
            config.root / "Dockerfile",
        ),
        _generate_hassfest_dockerimage(config, timeout, package_versions),
    ]


def validate(integrations: dict[str, Integration], config: Config) -> None:
    """Validate dockerfile."""
    docker_files = _generate_files(config)
    config.cache["docker"] = docker_files

    for file in docker_files:
        if file.content != file.path.read_text():
            config.add_error(
                "docker",
                f"File {file.path} is not up to date. Run python3 -m script.hassfest",
                fixable=True,
            )


def generate(integrations: dict[str, Integration], config: Config) -> None:
    """Generate dockerfile."""
    for file in _generate_files(config):
        file.path.write_text(file.content)
