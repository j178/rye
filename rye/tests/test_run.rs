use crate::common::{rye_cmd_snapshot, Space};
use std::fs;
use toml_edit::{table, value, Array};

mod common;

#[test]
fn test_run_list() {
    let space = Space::new();
    space.init("my-project");

    let status = space
        .rye_cmd()
        .arg("add")
        .arg("Flask==3.0.0")
        .arg("--sync")
        .status()
        .unwrap();
    assert!(status.success());

    space.edit_toml("pyproject.toml", |doc| {
        let mut scripts = table();
        scripts["hello"] = value("echo hello");
        doc["tool"]["rye"]["scripts"] = scripts;
    });
    rye_cmd_snapshot!(space.rye_cmd().arg("run").arg("--list"), @r###"
    success: true
    exit_code: 0
    ----- stdout -----
    flask
    hello (echo hello)
    python
    python3
    python3.12

    ----- stderr -----
    "###);
}

#[test]
fn test_basic_run() {
    let space = Space::new();
    space.init("my-project");

    // Run a virtualenv script
    let status = space
        .rye_cmd()
        .arg("add")
        .arg("Flask==3.0.0")
        .arg("--sync")
        .status()
        .unwrap();
    assert!(status.success());
    rye_cmd_snapshot!(space.rye_cmd().arg("run").arg("flask").arg("--version"), @r###"
    success: true
    exit_code: 0
    ----- stdout -----
    Python 3.12.2
    Flask 3.0.0
    Werkzeug 3.0.1

    ----- stderr -----
    "###);

    // Run a non-existing script
    rye_cmd_snapshot!(space.rye_cmd().arg("run").arg("not_exist_script"), @r###"
    success: false
    exit_code: 1
    ----- stdout -----

    ----- stderr -----
    error: invalid or unknown script 'not_exist_script'
    "###);

    let init_script = space
        .project_path()
        .join("src")
        .join("my_project")
        .join("__init__.py");
    fs::write(
        &init_script,
        "def hello():\n    print('Hello from my-project!')\n    return 0",
    )
    .unwrap();

    let env_file = space.project_path().join("env_file");
    fs::write(&env_file, r#"HELLO="Hello from script_6!""#).unwrap();

    // Run Rye scripts
    space.edit_toml("pyproject.toml", |doc| {
        let mut scripts = table();
        scripts["script_1"] = value(r#"python -c 'print("Hello from script_1!")'"#);
        scripts["script_2"]["cmd"] = value(r#"python -c 'print("Hello from script_2!")'"#);
        scripts["script_3"]["call"] = value("my_project:hello");
        scripts["script_4"]["chain"] =
            value(Array::from_iter(["script_1", "script_2", "script_3"]));

        scripts["script_5"]["cmd"] = value(r#"python -c 'import os; print(os.getenv("HELLO"))'"#);
        scripts["script_5"]["env"]["HELLO"] = value("Hello from script_5!");

        scripts["script_6"]["cmd"] = value(r#"python -c 'import os; print(os.getenv("HELLO"))'"#);
        scripts["script_6"]["env-file"] = value(env_file.to_string_lossy().into_owned());

        doc["tool"]["rye"]["scripts"] = scripts;
    });

    rye_cmd_snapshot!(space.rye_cmd().arg("run").arg("script_1"), @r###"
    success: true
    exit_code: 0
    ----- stdout -----
    Hello from script_1!

    ----- stderr -----
    "###);
    rye_cmd_snapshot!(space.rye_cmd().arg("run").arg("script_2"), @r###"
    success: true
    exit_code: 0
    ----- stdout -----
    Hello from script_2!

    ----- stderr -----
    "###);
    rye_cmd_snapshot!(space.rye_cmd().arg("run").arg("script_3"), @r###"
    success: true
    exit_code: 0
    ----- stdout -----
    Hello from my-project!

    ----- stderr -----
    "###);
    rye_cmd_snapshot!(space.rye_cmd().arg("run").arg("script_4"), @r###"
    success: true
    exit_code: 0
    ----- stdout -----
    Hello from script_1!
    Hello from script_2!
    Hello from my-project!

    ----- stderr -----
    "###);
    rye_cmd_snapshot!(space.rye_cmd().arg("run").arg("script_5"), @r###"
    success: true
    exit_code: 0
    ----- stdout -----
    Hello from script_5!

    ----- stderr -----
    "###);
    rye_cmd_snapshot!(space.rye_cmd().arg("run").arg("script_6"), @r###"
    success: true
    exit_code: 0
    ----- stdout -----
    Hello from script_6!

    ----- stderr -----
    "###);
}

#[test]
fn test_run_name_collision() {
    let space = Space::new();
    space.init("my-project");

    let status = space
        .rye_cmd()
        .arg("add")
        .arg("Flask==3.0.0")
        .arg("--sync")
        .status()
        .unwrap();
    assert!(status.success());

    space.edit_toml("pyproject.toml", |doc| {
        doc["tool"]["rye"]["scripts"] = table();
        doc["tool"]["rye"]["scripts"]["flask"] =
            value(r#"python -c 'print("flask from rye script")'"#);
    });
    rye_cmd_snapshot!(space.rye_cmd().arg("run").arg("flask").arg("--version"), @r###"
    success: true
    exit_code: 0
    ----- stdout -----
    Python 3.12.2
    Flask 3.0.0
    Werkzeug 3.0.1

    ----- stderr -----
    "###);
}
