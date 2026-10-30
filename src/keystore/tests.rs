use super::*;

fn plan() -> SocketPlan {
    SocketPlan::new("hcl-test", "lair")
}

/// The config lair writes: the socket address is a URL, so a space is `%20`
/// there and a plain space in the two file paths. On Windows, a named pipe.
fn lair_style_config(dir: &Path) -> String {
    #[cfg(not(windows))]
    let url = format!("unix://{}/socket?k=AbC-123_x", dir.to_string_lossy().replace(' ', "%20"));
    #[cfg(windows)]
    let url = "named-pipe:\\\\.\\pipe\\Xy7_original?k=AbC-123_x".to_string();
    format!(
        "connectionUrl: {url}\n\n# The pid file for managing a running lair-keystore process\npidFile: {0}\n\n\
         # The sqlcipher store file for persisting secrets\nstoreFile: {1}\n\nsignatureFallback: none\n\
         databaseSalt: GMNSqdxN_Mg5mI5QYT4IIg\nruntimeSecretsContextKey:\n- k-1Ryqx6JQPrs4OM\n- PSaaiPEfbOOOFVEV\n",
        dir.join("pid_file").display(),
        dir.join("store_file").display()
    )
}

fn key_of(dir: &Path, key: &str) -> String {
    super::read_key(dir, key).unwrap()
}

// ── Sockets and the config ──────────────────────────────────────────────

#[cfg(not(windows))]
#[test]
fn two_stores_under_one_root_get_different_runtime_sockets() {
    let root = Path::new("/Users/someone/Library/Application Support/com.example.app/identities/0123456789abcdef");
    let first = runtime_socket_path(&root.join("lair"), &plan());
    let second = runtime_socket_path(&root.join("lair-07"), &plan());
    assert_ne!(first, second);
    assert_eq!(first, short_socket_path(root, &plan()), "the first store keeps the name existing configs point at");
    assert_eq!(second, short_socket_path(&root.join("lair-07"), &plan()));
    assert!(first.parent().unwrap().ends_with("hcl-test") || first.parent().unwrap().to_string_lossy().contains("/tmp/hcl-test-"));
}

#[cfg(not(windows))]
#[test]
fn a_too_long_socket_moves_to_the_runtime_folder_and_keeps_its_key() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("x".repeat(110));
    let lair = root.join("lair");
    std::fs::create_dir_all(&lair).unwrap();
    std::fs::write(config_path(&lair), lair_style_config(&lair)).unwrap();
    ensure_socket_fits(&lair, &plan()).unwrap();
    let url = read_connection_url(&lair).unwrap();
    let sock = socket_path_from_url(&url).unwrap();
    assert_eq!(sock, short_socket_path(&root, &plan()));
    assert!(socket_fits(&sock), "{sock:?}");
    assert!(url.ends_with("?k=AbC-123_x"), "connection key kept");
    assert!(sock.parent().unwrap().is_dir(), "socket folder created");
    let after = std::fs::read_to_string(config_path(&lair)).unwrap();
    assert!(after.contains(&format!("pidFile: {}", lair.join("pid_file").display())), "other paths untouched");
    assert!(after.contains("runtimeSecretsContextKey:\n- k-1Ryqx6JQPrs4OM"), "the rest of the config untouched");
    // The per-start repoint keeps the moved socket, and a second fit is a no-op.
    assert!(!repoint_config(&lair, &plan()).unwrap());
    ensure_socket_fits(&lair, &plan()).unwrap();
    assert_eq!(std::fs::read_to_string(config_path(&lair)).unwrap(), after);
}

#[cfg(not(windows))]
#[test]
fn a_fitting_socket_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let lair = tmp.path().join("lair");
    std::fs::create_dir_all(&lair).unwrap();
    let original = lair_style_config(&lair);
    std::fs::write(config_path(&lair), &original).unwrap();
    ensure_socket_fits(&lair, &plan()).unwrap();
    assert_eq!(std::fs::read_to_string(config_path(&lair)).unwrap(), original);
}

#[cfg(not(windows))]
#[test]
fn a_moved_store_is_repointed_when_its_path_has_a_space() {
    let tmp = tempfile::tempdir().unwrap();
    let old = tmp.path().join("Application Support").join("app").join("lair");
    let new = tmp.path().join("Application Support").join("app").join("profiles").join("local").join("lair");
    std::fs::create_dir_all(&new).unwrap();
    std::fs::write(config_path(&new), lair_style_config(&old)).unwrap();
    assert!(repoint_config(&new, &plan()).unwrap());
    let url = read_connection_url(&new).unwrap();
    assert_eq!(socket_path_from_url(&url).unwrap(), new.join("socket"), "the socket follows the move");
    assert!(url.contains("Application%20Support"), "and stays an encoded URL: {url}");
    assert!(url.ends_with("?k=AbC-123_x"));
    assert_eq!(key_of(&new, "pidFile"), new.join("pid_file").to_string_lossy());
    assert_eq!(key_of(&new, "storeFile"), new.join("store_file").to_string_lossy());
    assert!(std::fs::read_to_string(config_path(&new)).unwrap().contains("signatureFallback: none"));
    assert!(!repoint_config(&new, &plan()).unwrap(), "a second start changes nothing");
}

#[cfg(not(windows))]
#[test]
fn a_config_half_fixed_by_a_text_replace_is_healed() {
    let tmp = tempfile::tempdir().unwrap();
    let old = tmp.path().join("Application Support").join("app").join("lair");
    let new = tmp.path().join("Application Support").join("app").join("profiles").join("local").join("lair");
    std::fs::create_dir_all(&new).unwrap();
    let half = lair_style_config(&old).replace(&*old.to_string_lossy(), &new.to_string_lossy());
    assert!(half.contains("app/lair/socket"), "precondition: the encoded socket address is still the old one");
    std::fs::write(config_path(&new), half).unwrap();
    assert!(repoint_config(&new, &plan()).unwrap());
    assert!(read_connection_url(&new).unwrap().contains("profiles/local/lair/socket"));
}

#[test]
fn a_config_in_place_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("Application Support").join("lair");
    std::fs::create_dir_all(&dir).unwrap();
    let original = lair_style_config(&dir);
    std::fs::write(config_path(&dir), &original).unwrap();
    assert!(!repoint_config(&dir, &plan()).unwrap());
    assert_eq!(std::fs::read_to_string(config_path(&dir)).unwrap(), original);
}

#[test]
fn yaml_values_round_trip_through_quoting() {
    for v in ["/plain/path", "/a: b/c", "/it's/here", "-starts-with-dash", "C:\\Users\\Eric\\AppData"] {
        let line = yaml_scalar(v);
        assert_eq!(yaml_value(&line), v, "{line}");
    }
    assert_eq!(yaml_scalar("/plain/path"), "/plain/path");
    assert_eq!(yaml_value("\"C:\\\\x\""), "C:\\x");
}

#[test]
fn lair_logs_prefer_stderr_and_say_when_there_is_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(read_logs(tmp.path()), "(no output)");
    std::fs::write(tmp.path().join("lair-stdout.log"), "out").unwrap();
    assert_eq!(read_logs(tmp.path()), "out");
    std::fs::write(tmp.path().join("lair-stderr.log"), "passphrase rejected").unwrap();
    assert_eq!(read_logs(tmp.path()), "passphrase rejected");
}

// ── The store copy ──────────────────────────────────────────────────────

/// A store as lair leaves it: config, main file, write-ahead log and index,
/// a pid file and logs that must not come along.
fn fake_store(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(config_path(dir), lair_style_config(dir)).unwrap();
    std::fs::write(dir.join("store_file"), vec![1u8; 4096]).unwrap();
    std::fs::write(dir.join("store_file-wal"), vec![2u8; 70_000]).unwrap();
    std::fs::write(dir.join("store_file-shm"), vec![3u8; 32_768]).unwrap();
    std::fs::write(dir.join("pid_file"), "999999999").unwrap();
    std::fs::write(dir.join("lair-stderr.log"), "old run").unwrap();
}

fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| (e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).unwrap()))
        .collect();
    v.sort();
    v
}

#[test]
fn a_copy_carries_every_store_file_and_names_only_itself() {
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("Application Support").join("lair");
    let to = tmp.path().join("Application Support").join("lair-07");
    fake_store(&from);
    let before = snapshot(&from);

    let copied = copy_store(&from, &to, &plan()).unwrap();
    assert_eq!(copied.dir, to);
    assert_eq!(copied.bytes, 4096 + 70_000 + 32_768);
    assert_eq!(snapshot(&from), before, "the source is untouched");
    for f in STORE_FILES {
        assert_eq!(std::fs::read(to.join(f)).unwrap(), std::fs::read(from.join(f)).unwrap(), "{f}");
    }
    assert!(!to.join("pid_file").exists() && !to.join("lair-stderr.log").exists(), "run files stay behind");
    assert_eq!(key_of(&to, "storeFile"), to.join("store_file").to_string_lossy());
    assert_eq!(key_of(&to, "pidFile"), to.join("pid_file").to_string_lossy());
    let url = read_connection_url(&to).unwrap();
    assert_eq!(url, copied.connection_url);
    assert!(url.ends_with("?k=AbC-123_x"), "the connection key is kept");
    #[cfg(not(windows))]
    assert_eq!(socket_path_from_url(&url).unwrap(), to.join("socket"));
    #[cfg(windows)]
    assert!(url.starts_with("named-pipe:\\\\.\\pipe\\lair-") && !url.contains("Xy7_original"), "{url}");
    let config = std::fs::read_to_string(config_path(&to)).unwrap();
    assert!(config.contains("databaseSalt: GMNSqdxN_Mg5mI5QYT4IIg\nruntimeSecretsContextKey:\n- k-1Ryqx6JQPrs4OM"), "secrets kept as they are");
    let stamp = std::fs::read_to_string(to.join(COPIED_FROM_FILE)).unwrap();
    assert!(stamp.starts_with(&*from.to_string_lossy()));
    assert!(!repoint_config(&to, &plan()).unwrap(), "the copy is already in place");
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path().join("Application Support"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".copying-"))
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn a_copy_never_replaces_a_store_but_takes_an_empty_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("lair");
    let to = tmp.path().join("lair-07");
    fake_store(&from);
    std::fs::create_dir_all(&to).unwrap();
    std::fs::write(to.join("store_file"), b"someone's keys").unwrap();
    let err = copy_store(&from, &to, &plan()).unwrap_err();
    assert!(matches!(err, Error::KeyStore(KeyStoreError::DestinationExists(_))), "{err}");
    assert_eq!(std::fs::read(to.join("store_file")).unwrap(), b"someone's keys");
    std::fs::remove_file(to.join("store_file")).unwrap();
    copy_store(&from, &to, &plan()).unwrap();
}

#[test]
fn a_copy_that_still_names_the_source_is_refused_and_leaves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("lair");
    let to = tmp.path().join("lair-07");
    fake_store(&from);
    let mut config = std::fs::read_to_string(config_path(&from)).unwrap();
    config.push_str(&format!("someLaterSetting: {}\n", from.join("extra").display()));
    std::fs::write(config_path(&from), config).unwrap();
    let err = copy_store(&from, &to, &plan()).unwrap_err();
    match err {
        Error::KeyStore(KeyStoreError::CopyStillNamesSource { key }) => assert_eq!(key, "someLaterSetting"),
        other => panic!("{other}"),
    }
    assert!(!to.exists());
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1, "no unfinished copy left");
}

#[test]
fn the_source_check_matches_whole_paths_in_every_spelling() {
    let from = Path::new("/a/Application Support/lair");
    let lines = |s: &str| vec![s.to_string()];
    assert!(copy::names_source_for_test(&lines("storeFile: /a/Application Support/lair-07/store_file"), from).is_none());
    assert!(copy::names_source_for_test(&lines("storeFile: /a/Application Support/lair/store_file"), from).is_some());
    assert!(copy::names_source_for_test(&lines("connectionUrl: unix:///a/Application%20Support/lair/socket?k=x"), from).is_some());
    assert!(copy::names_source_for_test(&lines("x: \\a\\Application Support\\lair\\store_file"), from).is_some());
    assert!(copy::names_source_for_test(&lines("x: '/a/Application Support/lair'"), from).is_some());
    assert!(copy::names_source_for_test(&lines("x: /a/Application Support/lair"), from).is_some());
    assert_eq!(
        copy::names_source_for_test(&lines("- /a/Application Support/lair/x"), from).as_deref(),
        Some("a config line"),
        "a line without a key never quotes the line itself"
    );
}

#[test]
fn a_running_source_is_one_whose_pid_is_a_live_lair() {
    let tmp = tempfile::tempdir().unwrap();
    let pid_file = tmp.path().join("pid_file");
    let me = std::process::id().to_string();
    std::fs::write(&pid_file, &me).unwrap();
    assert!(copy::pid_file_names_live_for_test(&pid_file, |_| true));
    assert!(!copy::pid_file_names_live_for_test(&pid_file, |_| false), "a live process that is not lair");
    std::fs::write(&pid_file, "").unwrap();
    assert!(!copy::pid_file_names_live_for_test(&pid_file, |_| true), "the empty file a power cut leaves");
    std::fs::write(&pid_file, "999999999").unwrap();
    assert!(!copy::pid_file_names_live_for_test(&pid_file, |_| true), "a pid nobody has");
}

#[test]
fn an_unfinished_copy_is_cleared_and_the_copy_may_not_be_inside_the_source() {
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("lair");
    let to = tmp.path().join("lair-07");
    fake_store(&from);
    std::fs::create_dir_all(tmp.path().join("lair-07.copying-12345")).unwrap();
    std::fs::write(tmp.path().join("lair-07.copying-12345").join("store_file"), b"half").unwrap();
    copy_store(&from, &to, &plan()).unwrap();
    assert!(!tmp.path().join("lair-07.copying-12345").exists());
    let inside = copy_store(&from, &from.join("nested"), &plan()).unwrap_err();
    assert!(matches!(inside, Error::KeyStore(KeyStoreError::Config { .. })), "{inside}");
}

#[cfg(not(windows))]
#[test]
fn a_copy_too_deep_for_a_socket_gets_its_runtime_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("lair");
    let to = tmp.path().join("y".repeat(110)).join("lair-07");
    fake_store(&from);
    let copied = copy_store(&from, &to, &plan()).unwrap();
    assert_eq!(socket_path_from_url(&copied.connection_url).unwrap(), runtime_socket_path(&to, &plan()));
}

// ── Live: the real lair binaries ────────────────────────────────────────

/// S3 as a library test, with the real binaries: keys made on lair 0.6.3
/// (one imported, two that cannot be exported), the store copied, lair
/// 0.7.1 on the copy signs with every key exactly as 0.6.3 does, and the
/// original still opens on 0.6.3 afterwards, unchanged.
///
/// `HC_LINES_LAIR_06=<lair 0.6.3> HC_LINES_LAIR_07=<lair 0.7.1> cargo test --lib -- --ignored live_`
#[cfg(all(feature = "line-06", feature = "line-07"))]
#[tokio::test]
#[ignore]
async fn live_a_copied_06_store_signs_identically_on_07() {
    use crate::process::stop_gracefully;
    let bin = |var: &str| PathBuf::from(std::env::var(var).unwrap_or_else(|_| panic!("set {var}")));
    let (lair06, lair07) = (bin("HC_LINES_LAIR_06"), bin("HC_LINES_LAIR_07"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("Application Support").join("profile");
    let (from, to) = (root.join("lair"), root.join("lair-07"));
    let pass = "live test passphrase";
    let msg: &[u8] = b"flowsta-hc-lines: the same key signs the same bytes";

    let (mut child, url) = start(&from, &lair06, pass, &plan()).unwrap();
    wait_ready(&url, Duration::from_secs(15), &mut child, &from).await.unwrap();
    let client = v06::connect_with_retries(&url, pass, &mut child, &from).await.unwrap();
    let imported = v06::import_seed(&client, &[9u8; 32], "device").await.unwrap();
    let ai1 = v06::new_seed(&client, "ai-1").await.unwrap();
    let ai2 = v06::new_seed(&client, "ai-2").await.unwrap();
    let mut sigs06 = Vec::new();
    for k in [imported, ai1, ai2] {
        let s = client.sign_by_pub_key(k.into(), None, msg.into()).await.unwrap();
        sigs06.push(s.0.to_vec());
    }
    drop(client);
    let refused = copy_store(&from, &to, &plan()).unwrap_err();
    assert!(matches!(refused, Error::KeyStore(KeyStoreError::SourceRunning(_))), "{refused}");
    stop_gracefully(&mut child, Duration::from_secs(2)).unwrap();
    let before: Vec<_> = STORE_FILES.iter().map(|f| std::fs::read(from.join(f)).ok()).collect();

    let copied = copy_store(&from, &to, &plan()).unwrap();
    let (mut child07, url07) = start(&to, &lair07, pass, &plan()).unwrap();
    assert_eq!(url07, copied.connection_url);
    wait_ready(&url07, Duration::from_secs(15), &mut child07, &to).await.unwrap();
    let c07 = v07::connect_with_retries(&url07, pass, &mut child07, &to).await.unwrap();
    assert_eq!(v07::existing(&c07, "ai-1").await.unwrap(), ai1);
    assert_eq!(v07::existing(&c07, "ai-2").await.unwrap(), ai2);
    assert_eq!(v07::import_seed(&c07, &[9u8; 32], "device").await.unwrap(), imported, "the seed is reused, not re-imported");
    assert_eq!(v07::new_seed(&c07, "ai-1").await.unwrap(), ai1);
    for (k, want) in [imported, ai1, ai2].into_iter().zip(&sigs06) {
        let s = c07.sign_by_pub_key(k.into(), None, msg.into()).await.unwrap();
        assert_eq!(&s.0.to_vec(), want, "0.7.1 signs as 0.6.3 did");
    }
    let fresh = v07::new_seed(&c07, "ai-made-on-07").await.unwrap();
    drop(c07);
    stop_gracefully(&mut child07, Duration::from_secs(2)).unwrap();

    let after: Vec<_> = STORE_FILES.iter().map(|f| std::fs::read(from.join(f)).ok()).collect();
    assert_eq!(before, after, "the original store is byte for byte as it was");
    let (mut child, url) = start(&from, &lair06, pass, &plan()).unwrap();
    wait_ready(&url, Duration::from_secs(15), &mut child, &from).await.unwrap();
    let client = v06::connect_with_retries(&url, pass, &mut child, &from).await.unwrap();
    assert_eq!(v06::existing(&client, "ai-2").await.unwrap(), ai2, "the original still opens on 0.6.3");
    let absent = v06::existing(&client, "ai-made-on-07").await.unwrap_err();
    assert!(matches!(absent, Error::KeyStore(KeyStoreError::KeyAbsent { .. })), "{absent}");
    assert_ne!(fresh, ai1);
    drop(client);
    stop_gracefully(&mut child, Duration::from_secs(2)).unwrap();
}
