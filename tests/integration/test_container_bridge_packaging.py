from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_server_image_builds_and_copies_real_bridge_runtime() -> None:
    dockerfile = (REPOSITORY_ROOT / "deploy" / "server.Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "ARG OPENHITLS_REF=a6b28e09f186dd0402b1236d8b4455842694fce4" in dockerfile
    assert 'test "$(git -C openhitls rev-parse HEAD)" = "$OPENHITLS_REF"' in dockerfile
    assert "-DBUILD_TESTING=ON" in dockerfile
    assert "ctest --test-dir bridge/build --output-on-failure" in dockerfile
    for library in (
        "libcc_bridge.so",
        "libhitls_bsl.so",
        "libhitls_crypto.so",
        "libhitls_pki.so",
    ):
        assert library in dockerfile
    assert "bridge/wrapper /opt/cryptocampus/bridge/wrapper" in dockerfile
    assert "CC_BRIDGE_LIBRARY=/opt/cryptocampus/lib/libcc_bridge.so" in dockerfile


def test_compose_does_not_mask_image_bridge_with_host_directory() -> None:
    compose = (REPOSITORY_ROOT / "compose.yaml").read_text(encoding="utf-8")
    environment = (REPOSITORY_ROOT / ".env.example").read_text(encoding="utf-8")
    pipeline = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")

    assert "CRYPTOCAMPUS_BRIDGE_DIR" not in compose
    assert "target: /opt/cryptocampus/lib" not in compose
    assert "CRYPTOCAMPUS_BRIDGE_DIR" not in environment
    assert 'mkdir -p \'$release_path/deploy/runtime/lib\'' not in pipeline
