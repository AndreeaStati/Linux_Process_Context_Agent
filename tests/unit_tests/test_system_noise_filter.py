from filters.system_noise_filter import SystemNoiseFilter


def make_doc(
    name: str = "bash",
    executable: str = "/usr/bin/bash",
    args: list[str] | None = None,
    command_line: str | None = None,
) -> dict:
    if args is None:
        args = ["bash"]

    if command_line is None:
        command_line = " ".join(args)

    return {
        "event": {
            "category": ["process"],
            "type": ["start"],
            "action": "process_started",
        },
        "process": {
            "name": name,
            "executable": executable,
            "args": args,
            "command_line": command_line,
        },
    }


def test_drops_vscode_server_path():
    noise_filter = SystemNoiseFilter()

    doc = make_doc(
        name="sh",
        executable="/home/ubuntu/.vscode-server/server/out/cpuUsage.sh",
        args=[
            "/home/ubuntu/.vscode-server/server/out/cpuUsage.sh",
            "1234",
        ],
    )

    decision = noise_filter.evaluate(doc)

    assert decision.drop is True
    assert "vscode server" in decision.reason


def test_drops_cpu_usage_process_name():
    noise_filter = SystemNoiseFilter()

    doc = make_doc(
        name="cpuUsage.sh",
        executable="/usr/bin/cat",
        args=[
            "cat",
            "/proc/1234/stat",
        ],
    )

    decision = noise_filter.evaluate(doc)

    assert decision.drop is True
    assert "procfs polling" in decision.reason


def test_drops_cpu_usage_command_line():
    noise_filter = SystemNoiseFilter()

    doc = make_doc(
        name="sh",
        executable="/bin/sh",
        args=[
            "/bin/sh",
            "-c",
            "/home/ubuntu/.vscode-server/server/out/cpuUsage.sh 1234",
        ],
    )

    decision = noise_filter.evaluate(doc)

    assert decision.drop is True


def test_drops_proc_stat_sed_reader():
    noise_filter = SystemNoiseFilter()

    doc = make_doc(
        name="cpuUsage.sh",
        executable="/usr/bin/sed",
        args=[
            "sed",
            "-n",
            r"s/^cpu\s//p",
            "/proc/stat",
        ],
    )

    decision = noise_filter.evaluate(doc)

    assert decision.drop is True
    assert "procfs polling" in decision.reason


def test_drops_proc_pid_stat_cat_reader():
    noise_filter = SystemNoiseFilter()

    doc = make_doc(
        name="cpuUsage.sh",
        executable="/usr/bin/cat",
        args=[
            "cat",
            "/proc/1234/stat",
        ],
    )

    decision = noise_filter.evaluate(doc)

    assert decision.drop is True
    assert "procfs polling" in decision.reason


def test_drops_which_ps_inventory_command():
    noise_filter = SystemNoiseFilter()

    doc = make_doc(
        name="sh",
        executable="/usr/bin/which",
        args=[
            "which",
            "ps",
        ],
    )

    decision = noise_filter.evaluate(doc)

    assert decision.drop is True
    assert "process inventory" in decision.reason


def test_drops_ps_inventory_command():
    noise_filter = SystemNoiseFilter()

    doc = make_doc(
        name="sh",
        executable="/usr/bin/ps",
        args=[
            "/usr/bin/ps",
            "-ax",
            "-o",
            "pid=,ppid=,pcpu=,pmem=,command=",
        ],
    )

    decision = noise_filter.evaluate(doc)

    assert decision.drop is True
    assert "process inventory" in decision.reason


def test_allows_curl_process():
    noise_filter = SystemNoiseFilter()

    doc = make_doc(
        name="bash",
        executable="/usr/bin/curl",
        args=[
            "curl",
            "http://example.com",
        ],
        command_line="curl http://example.com",
    )

    decision = noise_filter.evaluate(doc)

    assert decision.drop is False
    assert decision.reason is None


def test_allows_generic_cat_file():
    noise_filter = SystemNoiseFilter()

    doc = make_doc(
        name="bash",
        executable="/usr/bin/cat",
        args=[
            "cat",
            "/etc/passwd",
        ],
        command_line="cat /etc/passwd",
    )

    decision = noise_filter.evaluate(doc)

    assert decision.drop is False
    assert decision.reason is None

def test_drops_git_worktree_inventory_command():
    noise_filter = SystemNoiseFilter()

    doc = make_doc(
        name="MainThread",
        executable="/usr/bin/git",
        args=[
            "git",
            "worktree",
            "list",
            "--porcelain",
        ],
        command_line="git worktree list --porcelain",
    )

    decision = noise_filter.evaluate(doc)

    assert decision.drop is True
    assert "process inventory" in decision.reason