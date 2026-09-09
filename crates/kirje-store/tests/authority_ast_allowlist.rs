use std::{
    fs,
    path::{Path, PathBuf},
};

use syn::{
    ExprCall, ExprPath, ImplItemFn, ItemFn, ItemUse, Path as SynPath, UseTree,
    visit::{self, Visit},
};

struct KirjeCredentialAstVisitor<'a> {
    crate_name: &'a str,
    file_rel_path: &'a str,
    current_fn: Option<String>,
    delete_only_calls: Vec<CallSiteRecord>,
    locator_references: Vec<RefRecord>,
    reexports: Vec<ReexportRecord>,
    foreign_crate_uses: Vec<ForeignUseRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallSiteRecord {
    crate_name: String,
    file_rel_path: String,
    enclosing_fn: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RefRecord {
    crate_name: String,
    file_rel_path: String,
    enclosing_fn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReexportRecord {
    crate_name: String,
    file_rel_path: String,
    target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForeignUseRecord {
    crate_name: String,
    file_rel_path: String,
    use_path: String,
}

impl<'a> KirjeCredentialAstVisitor<'a> {
    fn new(crate_name: &'a str, file_rel_path: &'a str) -> Self {
        Self {
            crate_name,
            file_rel_path,
            current_fn: None,
            delete_only_calls: Vec::new(),
            locator_references: Vec::new(),
            reexports: Vec::new(),
            foreign_crate_uses: Vec::new(),
        }
    }

    fn check_use_tree(&mut self, tree: &UseTree, is_pub: bool) {
        match tree {
            UseTree::Path(use_path) => {
                let segment = use_path.ident.to_string();
                if segment == "kirje_credential" {
                    if is_pub {
                        self.reexports.push(ReexportRecord {
                            crate_name: self.crate_name.to_owned(),
                            file_rel_path: self.file_rel_path.to_owned(),
                            target: segment,
                        });
                    }
                    if self.crate_name != "kirje-store" && self.crate_name != "kirje-credential" {
                        self.foreign_crate_uses.push(ForeignUseRecord {
                            crate_name: self.crate_name.to_owned(),
                            file_rel_path: self.file_rel_path.to_owned(),
                            use_path: "use kirje_credential::...".to_owned(),
                        });
                    }
                }
                self.check_use_tree(&use_path.tree, is_pub);
            }
            UseTree::Name(name) => {
                let id = name.ident.to_string();
                if (id == "DeleteOnlyLocator" || id == "delete_only" || id == "kirje_credential")
                    && is_pub
                {
                    self.reexports.push(ReexportRecord {
                        crate_name: self.crate_name.to_owned(),
                        file_rel_path: self.file_rel_path.to_owned(),
                        target: id,
                    });
                }
            }
            UseTree::Rename(rename) => {
                let id = rename.ident.to_string();
                if (id == "DeleteOnlyLocator" || id == "delete_only" || id == "kirje_credential")
                    && is_pub
                {
                    self.reexports.push(ReexportRecord {
                        crate_name: self.crate_name.to_owned(),
                        file_rel_path: self.file_rel_path.to_owned(),
                        target: id,
                    });
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.check_use_tree(item, is_pub);
                }
            }
            UseTree::Glob(_) => {}
        }
    }

    fn inspect_path(&mut self, path: &SynPath) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        if segments.is_empty() {
            return;
        }

        if segments.iter().any(|s| s == "DeleteOnlyLocator") {
            self.locator_references.push(RefRecord {
                crate_name: self.crate_name.to_owned(),
                file_rel_path: self.file_rel_path.to_owned(),
                enclosing_fn: self.current_fn.clone(),
            });
        }
    }
}

impl<'ast> Visit<'ast> for KirjeCredentialAstVisitor<'_> {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        let is_pub = matches!(node.vis, syn::Visibility::Public(_));
        self.check_use_tree(&node.tree, is_pub);
        visit::visit_item_use(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let previous = self.current_fn.take();
        self.current_fn = Some(node.sig.ident.to_string());
        visit::visit_item_fn(self, node);
        self.current_fn = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let previous = self.current_fn.take();
        self.current_fn = Some(node.sig.ident.to_string());
        visit::visit_impl_item_fn(self, node);
        self.current_fn = previous;
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let syn::Expr::Path(ExprPath { path, .. }) = &*node.func {
            let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
            let is_credential_delete_call = (segments.len() >= 2
                && segments[0] == "kirje_credential"
                && segments[1] == "delete_only")
                || (segments.len() == 1 && segments[0] == "delete_only");

            if is_credential_delete_call {
                self.delete_only_calls.push(CallSiteRecord {
                    crate_name: self.crate_name.to_owned(),
                    file_rel_path: self.file_rel_path.to_owned(),
                    enclosing_fn: self
                        .current_fn
                        .clone()
                        .unwrap_or_else(|| "<unknown>".to_owned()),
                });
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        self.inspect_path(path);
        visit::visit_path(self, path);
    }
}

fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if dir.exists() {
        for entry in fs::read_dir(dir).expect("readable dir") {
            let entry = entry.expect("valid entry");
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_rs_files(&path));
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn workspace_cargo_dependency_allowlist_is_strictly_enforced() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root");

    let crates_dir = workspace_root.join("crates");
    let mut dependents = Vec::new();

    for entry in fs::read_dir(&crates_dir).expect("crates directory exists") {
        let entry = entry.expect("valid crate directory");
        let path = entry.path();
        if path.is_dir() {
            let cargo_toml = path.join("Cargo.toml");
            if cargo_toml.exists() {
                let content = fs::read_to_string(&cargo_toml).expect("readable Cargo.toml");
                let crate_name = path.file_name().unwrap().to_str().unwrap();
                if crate_name != "kirje-credential" && content.contains("kirje-credential") {
                    dependents.push(crate_name.to_owned());
                }
            }
        }
    }

    assert_eq!(
        dependents,
        vec!["kirje-store".to_string()],
        "Only kirje-store may depend on kirje-credential; found illegal dependents: {dependents:?}"
    );
}

#[test]
fn exhaustive_production_ast_allowlist_for_credential_deletion() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root");

    let crates_dir = workspace_root.join("crates");
    let all_crates = [
        "kirje-cli",
        "kirje-core",
        "kirje-credential",
        "kirje-local-io",
        "kirje-mcp",
        "kirje-protocol",
        "kirje-runtime",
        "kirje-store",
    ];

    let mut total_delete_only_calls = Vec::new();
    let mut total_reexports = Vec::new();
    let mut total_foreign_uses = Vec::new();
    let mut store_locator_refs = Vec::new();

    for crate_name in &all_crates {
        let crate_src = crates_dir.join(crate_name).join("src");
        let rs_files = collect_rs_files(&crate_src);

        for file_path in rs_files {
            let rel_path = file_path
                .strip_prefix(&crates_dir)
                .unwrap()
                .to_str()
                .unwrap();
            let source = fs::read_to_string(&file_path).expect("readable rs file");
            let ast = syn::parse_file(&source)
                .unwrap_or_else(|e| panic!("failed to parse AST for {rel_path}: {e}"));

            let mut visitor = KirjeCredentialAstVisitor::new(crate_name, rel_path);
            visitor.visit_file(&ast);

            total_delete_only_calls.extend(visitor.delete_only_calls);
            total_reexports.extend(visitor.reexports);
            total_foreign_uses.extend(visitor.foreign_crate_uses);
            if *crate_name == "kirje-store" {
                store_locator_refs.extend(visitor.locator_references);
            }
        }
    }

    assert!(
        total_reexports.is_empty(),
        "Detected forbidden public re-export of kirje-credential: {total_reexports:?}"
    );

    assert!(
        total_foreign_uses.is_empty(),
        "Detected illegal use of kirje_credential outside kirje-store: {total_foreign_uses:?}"
    );

    assert_eq!(
        total_delete_only_calls.len(),
        1,
        "Expected exactly one production call to delete_only across the workspace, but found: {total_delete_only_calls:?}"
    );

    let call = &total_delete_only_calls[0];
    assert_eq!(call.crate_name, "kirje-store");
    assert!(
        call.file_rel_path.ends_with("authority.rs"),
        "delete_only must be called only in authority.rs, found: {}",
        call.file_rel_path
    );
    assert_eq!(
        call.enclosing_fn, "apply_credential_cleanup_delete",
        "delete_only must be called strictly within apply_credential_cleanup_delete"
    );

    for loc_ref in &store_locator_refs {
        assert!(
            loc_ref.file_rel_path.ends_with("authority.rs"),
            "DeleteOnlyLocator must only be referenced in authority.rs, found: {}",
            loc_ref.file_rel_path
        );
    }
}

#[test]
fn ast_visitor_detects_adversarial_bypasses() {
    let bad_code_1 = r"
        pub use kirje_credential::delete_only;
    ";
    let ast1 = syn::parse_file(bad_code_1).unwrap();
    let mut v1 = KirjeCredentialAstVisitor::new("kirje-runtime", "runtime.rs");
    v1.visit_file(&ast1);
    assert!(!v1.reexports.is_empty());

    let bad_code_2 = r"
        fn rogue_fn() {
            kirje_credential::delete_only(loc);
        }
    ";
    let ast2 = syn::parse_file(bad_code_2).unwrap();
    let mut v2 = KirjeCredentialAstVisitor::new("kirje-store", "authority.rs");
    v2.visit_file(&ast2);
    assert_eq!(v2.delete_only_calls.len(), 1);
    assert_eq!(v2.delete_only_calls[0].enclosing_fn, "rogue_fn");

    let bad_code_3 = r"
        use kirje_credential::DeleteOnlyLocator;
    ";
    let ast3 = syn::parse_file(bad_code_3).unwrap();
    let mut v3 = KirjeCredentialAstVisitor::new("kirje-cli", "main.rs");
    v3.visit_file(&ast3);
    assert!(!v3.foreign_crate_uses.is_empty());
}
