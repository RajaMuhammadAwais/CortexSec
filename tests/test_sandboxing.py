from cortexsec.core.sandbox import DockerSandboxRunner


def test_sandbox_blocks_etc_passwd_access():
    runner = DockerSandboxRunner(workspace="/workspace")
    result = runner.run("cat /etc/passwd")
    assert result.exit_code == 126
    assert "blocked-by-sandbox:path-access-denied" in result.stderr


def test_sandbox_blocks_absolute_paths_outside_workspace():
    runner = DockerSandboxRunner(workspace="/workspace")
    result = runner.run("cat /var/log/syslog")
    assert result.exit_code == 126
    assert "path-outside-workspace" in result.stderr
