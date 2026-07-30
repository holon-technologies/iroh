#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use quote::ToTokens;
use syn::{
    ExprCall, ExprMethodCall, ExprPath, ImplItemFn, ItemFn, ItemImpl, ItemMod, ItemUse,
    Path as SynPath, TypePath, UseTree,
    visit::{self, Visit},
};

const SOURCE_ROOTS: [&str; 8] = [
    "krikos",
    "krikos-base",
    "krikos-resolver",
    "krikos-dns",
    "krikos-dns-server",
    "krikos-relay",
    "krikos-runtime",
    "krikos-sim",
];
const MAX_SOURCE_FILES: usize = 20_000;
const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_OCCURRENCES: usize = 100_000;

type DynError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Check,
    Update,
}

#[derive(Debug)]
struct Args {
    mode: Mode,
    root: PathBuf,
    baseline: PathBuf,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Boundary {
    category: &'static str,
    path: String,
    owner: String,
    api: String,
    ordinal: usize,
}

impl fmt::Display for Boundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}\t{}\t{}\t{}\t{}",
            self.category, self.path, self.owner, self.api, self.ordinal
        )
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("semantic determinism boundary check failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), DynError> {
    let args = parse_args(env::args().skip(1))?;
    let root = args.root.canonicalize()?;
    let boundaries = collect_boundaries(&root)?;
    match args.mode {
        Mode::Update => update_baseline(&args.baseline, &boundaries),
        Mode::Check => check_baseline(&args.baseline, &boundaries),
    }
}

fn parse_args(arguments: impl Iterator<Item = String>) -> Result<Args, DynError> {
    let mut mode = None;
    let mut root = env::current_dir()?;
    let mut baseline = None;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--check" => set_mode(&mut mode, Mode::Check)?,
            "--update" => set_mode(&mut mode, Mode::Update)?,
            "--root" => {
                root = PathBuf::from(
                    arguments
                        .next()
                        .ok_or("--root requires a directory argument")?,
                );
            }
            "--baseline" => {
                baseline = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or("--baseline requires a file argument")?,
                ));
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {argument}").into()),
        }
    }
    let mode = mode.ok_or("choose exactly one of --check or --update")?;
    let baseline =
        baseline.unwrap_or_else(|| root.join("scripts/determinism-boundaries.semantic.txt"));
    Ok(Args {
        mode,
        root,
        baseline,
    })
}

fn set_mode(selected: &mut Option<Mode>, requested: Mode) -> Result<(), DynError> {
    if selected.replace(requested).is_some() {
        return Err("choose exactly one of --check or --update".into());
    }
    Ok(())
}

fn print_usage() {
    eprintln!("Usage: determinism-checker (--check|--update) [--root DIR] [--baseline FILE]");
}

fn collect_boundaries(root: &Path) -> Result<BTreeSet<Boundary>, DynError> {
    let files = source_files(root)?;
    let mut counts: BTreeMap<(&'static str, String, String, String), usize> = BTreeMap::new();
    for file in files {
        let metadata = fs::metadata(&file)?;
        if metadata.len() > MAX_SOURCE_BYTES {
            return Err(format!(
                "Rust source exceeds {MAX_SOURCE_BYTES} bytes: {}",
                file.display()
            )
            .into());
        }
        let source = fs::read_to_string(&file)?;
        let syntax = syn::parse_file(&source)
            .map_err(|error| format!("failed to parse {}: {error}", file.display()))?;
        let relative = normalized_relative_path(root, &file)?;
        let aliases = collect_aliases(&syntax.items);
        let mut visitor = BoundaryVisitor::new(relative, aliases);
        visitor.visit_file(&syntax);
        for occurrence in visitor.occurrences {
            if counts.len() >= MAX_OCCURRENCES && !counts.contains_key(&occurrence) {
                return Err(format!(
                    "semantic boundary inventory exceeds {MAX_OCCURRENCES} unique occurrences"
                )
                .into());
            }
            let count = counts.entry(occurrence).or_default();
            *count = count
                .checked_add(1)
                .ok_or("semantic boundary occurrence count overflowed")?;
        }
    }

    let mut boundaries = BTreeSet::new();
    for ((category, path, owner, api), count) in counts {
        for ordinal in 1..=count {
            boundaries.insert(Boundary {
                category,
                path: path.clone(),
                owner: owner.clone(),
                api: api.clone(),
                ordinal,
            });
        }
    }
    Ok(boundaries)
}

fn source_files(root: &Path) -> Result<Vec<PathBuf>, DynError> {
    let mut files = Vec::new();
    for source_root in SOURCE_ROOTS {
        let candidate = root.join(source_root);
        if !candidate.is_dir() {
            return Err(format!(
                "determinism boundary source root missing: {} (below {}); a missing root would \
                 silently narrow the scan and could mask a stale/partial rename, so this is an \
                 error rather than a skip",
                source_root,
                root.display()
            )
            .into());
        }
        let mut pending = vec![candidate];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    pending.push(entry.path());
                } else if file_type.is_file()
                    && entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "rs")
                {
                    if files.len() >= MAX_SOURCE_FILES {
                        return Err(
                            format!("Rust source file count exceeds {MAX_SOURCE_FILES}").into()
                        );
                    }
                    files.push(entry.path());
                }
            }
        }
    }
    if files.is_empty() {
        return Err(format!("no Krikos Rust source roots found below {}", root.display()).into());
    }
    files.sort();
    Ok(files)
}

fn normalized_relative_path(root: &Path, file: &Path) -> Result<String, DynError> {
    let relative = file.strip_prefix(root)?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn collect_aliases(items: &[syn::Item]) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    for item in items {
        if let syn::Item::Use(item_use) = item {
            collect_item_use(item_use, &mut aliases);
        }
    }
    aliases
}

fn collect_item_use(item_use: &ItemUse, aliases: &mut BTreeMap<String, String>) {
    collect_use_tree(Vec::new(), &item_use.tree, aliases);
}

fn collect_use_tree(prefix: Vec<String>, tree: &UseTree, aliases: &mut BTreeMap<String, String>) {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix;
            next.push(path.ident.to_string());
            collect_use_tree(next, &path.tree, aliases);
        }
        UseTree::Name(name) => {
            let mut full = prefix;
            full.push(name.ident.to_string());
            aliases.insert(name.ident.to_string(), full.join("::"));
        }
        UseTree::Rename(rename) => {
            let mut full = prefix;
            full.push(rename.ident.to_string());
            aliases.insert(rename.rename.to_string(), full.join("::"));
        }
        UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_tree(prefix.clone(), tree, aliases);
            }
        }
        UseTree::Glob(_) => {}
    }
}

#[derive(Debug)]
struct BoundaryVisitor {
    path: String,
    aliases: BTreeMap<String, String>,
    owners: Vec<String>,
    occurrences: Vec<(&'static str, String, String, String)>,
}

impl BoundaryVisitor {
    fn new(path: String, aliases: BTreeMap<String, String>) -> Self {
        Self {
            path,
            aliases,
            owners: Vec::new(),
            occurrences: Vec::new(),
        }
    }

    fn owner(&self) -> String {
        if self.owners.is_empty() {
            "<module>".to_owned()
        } else {
            self.owners.join("::")
        }
    }

    fn record_api(&mut self, api: String) {
        for category in classify_api(&api) {
            self.occurrences
                .push((category, self.path.clone(), self.owner(), api.clone()));
        }
    }

    fn record_type(&mut self, api: String) {
        for category in classify_type(&api) {
            self.occurrences
                .push((category, self.path.clone(), self.owner(), api.clone()));
        }
    }

    fn resolve(&self, path: &SynPath) -> String {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let Some(first) = segments.first() else {
            return String::new();
        };
        if let Some(resolved) = self.aliases.get(first) {
            if segments.len() == 1 {
                resolved.clone()
            } else {
                format!("{resolved}::{}", segments[1..].join("::"))
            }
        } else {
            segments.join("::")
        }
    }

    fn push_owner(&mut self, owner: String) {
        self.owners.push(owner);
    }

    fn pop_owner(&mut self) {
        let removed = self.owners.pop();
        assert!(
            removed.is_some(),
            "semantic boundary visitor owner stack must remain balanced"
        );
    }
}

impl<'ast> Visit<'ast> for BoundaryVisitor {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        self.push_owner(node.ident.to_string());
        visit::visit_item_mod(self, node);
        self.pop_owner();
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.push_owner(node.sig.ident.to_string());
        visit::visit_item_fn(self, node);
        self.pop_owner();
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let implementation = node.self_ty.to_token_stream().to_string().replace(' ', "");
        self.push_owner(format!("impl<{implementation}>"));
        visit::visit_item_impl(self, node);
        self.pop_owner();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        self.push_owner(node.sig.ident.to_string());
        visit::visit_impl_item_fn(self, node);
        self.pop_owner();
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let syn::Expr::Path(function) = node.func.as_ref() {
            self.record_api(self.resolve(&function.path));
        } else {
            self.visit_expr(node.func.as_ref());
        }
        for argument in &node.args {
            self.visit_expr(argument);
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if matches!(method.as_str(), "with_jitter" | "with_jitter_seed") {
            self.record_api(format!("<method>::{method}"));
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_type_path(&mut self, node: &'ast TypePath) {
        if node.qself.is_none() {
            self.record_type(self.resolve(&node.path));
        }
        visit::visit_type_path(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        if node.qself.is_none() {
            let path = self.resolve(&node.path);
            if path.ends_with("::OsRng") || path == "OsRng" {
                self.record_type(path);
            }
        }
        visit::visit_expr_path(self, node);
    }
}

fn classify_api(api: &str) -> Vec<&'static str> {
    let mut categories = Vec::new();
    let last = api.rsplit("::").next().unwrap_or(api);
    if matches!(
        api,
        "tokio::spawn"
            | "tokio::task::spawn"
            | "tokio::task::spawn_blocking"
            | "n0_future::task::spawn"
            | "std::thread::spawn"
    ) || matches!(last, "spawn_blocking")
    {
        categories.push("spawn-task");
    }
    if matches!(
        last,
        "sleep"
            | "sleep_until"
            | "interval"
            | "interval_at"
            | "timeout"
            | "timeout_at"
            | "now"
            | "now_utc"
    ) && (api.contains("time")
        || api.contains("Instant")
        || api.contains("SystemTime")
        || api.contains("Timestamp"))
    {
        categories.push("clock-timer");
    }
    if matches!(
        last,
        "random"
            | "rng"
            | "thread_rng"
            | "getrandom"
            | "generate"
            | "with_jitter"
            | "with_jitter_seed"
    ) && (api.contains("rand")
        || api.contains("getrandom")
        || api.contains("SecretKey")
        || api.starts_with("<method>"))
    {
        categories.push("entropy-random");
    }
    if (matches!(last, "bind") && (api.contains("UdpSocket") || api.contains("TcpListener")))
        || matches!(last, "resolve_host" | "lookup_host" | "lookup_ip")
    {
        categories.push("network-environment");
    }
    if (matches!(last, "open") && api.contains("File"))
        || (last == "new" && (api.contains("OpenOptions") || api.contains("Command")))
        || (last == "var" && api.contains("env"))
        || api == "std::thread::spawn"
    {
        categories.push("external-state");
    }
    categories
}

fn classify_type(api: &str) -> Vec<&'static str> {
    let mut categories = Vec::new();
    let last = api.rsplit("::").next().unwrap_or(api);
    if last == "JoinSet" {
        categories.push("spawn-task");
    }
    if last == "OsRng" {
        categories.push("entropy-random");
    }
    if matches!(
        last,
        "UdpSocket" | "TcpListener" | "Monitor" | "State" | "Client"
    ) && (api.contains("net") || api.contains("portmapper") || api.contains("interfaces"))
    {
        categories.push("network-environment");
    }
    if matches!(
        last,
        "HashMap" | "HashSet" | "FxHashMap" | "FxHashSet" | "DashMap"
    ) {
        categories.push("unordered-collection");
    }
    categories
}

fn update_baseline(path: &Path, boundaries: &BTreeSet<Boundary>) -> Result<(), DynError> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("baseline path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or("baseline filename is not valid UTF-8")?,
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    for boundary in boundaries {
        writeln!(file, "{boundary}")?;
    }
    file.flush()?;
    fs::rename(&temporary, path)?;
    println!(
        "updated semantic determinism boundary baseline: {}",
        path.display()
    );
    Ok(())
}

fn check_baseline(path: &Path, boundaries: &BTreeSet<Boundary>) -> Result<(), DynError> {
    let expected = read_baseline(path)?;
    if &expected == boundaries {
        println!("semantic determinism boundary baseline is current");
        return Ok(());
    }
    eprintln!("semantic determinism boundary drift detected");
    for added in boundaries.difference(&expected) {
        eprintln!("  + {added}");
    }
    for removed in expected.difference(boundaries) {
        eprintln!("  - {removed}");
    }
    Err("classify the drift, then run scripts/check-determinism-semantic.sh --update".into())
}

fn read_baseline(path: &Path) -> Result<BTreeSet<Boundary>, DynError> {
    let source = fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read semantic baseline {}: {error}",
            path.display()
        )
    })?;
    let mut boundaries = BTreeSet::new();
    for (index, line) in source.lines().enumerate() {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(format!(
                "malformed semantic baseline at {}:{}",
                path.display(),
                index + 1
            )
            .into());
        }
        let category = match fields[0] {
            "spawn-task" => "spawn-task",
            "clock-timer" => "clock-timer",
            "entropy-random" => "entropy-random",
            "network-environment" => "network-environment",
            "external-state" => "external-state",
            "unordered-collection" => "unordered-collection",
            _ => {
                return Err(format!(
                    "unknown semantic boundary category at {}:{}",
                    path.display(),
                    index + 1
                )
                .into());
            }
        };
        let ordinal = fields[4].parse::<usize>()?;
        if ordinal == 0 || fields[1..4].iter().any(|field| field.is_empty()) {
            return Err(format!(
                "malformed semantic baseline at {}:{}",
                path.display(),
                index + 1
            )
            .into());
        }
        let inserted = boundaries.insert(Boundary {
            category,
            path: fields[1].to_owned(),
            owner: fields[2].to_owned(),
            api: fields[3].to_owned(),
            ordinal,
        });
        if !inserted {
            return Err(format!(
                "duplicate semantic boundary at {}:{}",
                path.display(),
                index + 1
            )
            .into());
        }
    }
    Ok(boundaries)
}
