//! Bounded, syntax-based resolution of commands passed to execution APIs.
//! No JavaScript runs: unknown values, writes, shadowing and cycles stop resolution.
use std::cell::Cell;
use std::collections::{HashMap, HashSet};

use filefacts::ParsedFile;
use filefacts::tree_sitter::Node;

use super::{Found, clip, commands, decode_escapes, execution_call, literal_specifier};

const NODE_BUDGET: usize = 8_000_000;
const VALUE_LIMIT: usize = 16_384;
/// Scopes nested deeper than any real program: past this, every name lookup
/// would walk a long chain, so the file resolves nothing.
const MAX_SCOPE_DEPTH: usize = 256;
/// [`Resolver::value`] steps one call site may take. Depth alone does not
/// bound the work: a template can name the same binding thousands of times at
/// every level, which multiplies.
const CALL_FUEL: u32 = 4_096;
/// [`Resolver::value`] steps the whole file may take.
const FILE_FUEL: u32 = 1_000_000;

#[derive(Clone)]
enum Value {
    Text(String),
    Api(String),
}

/// A scope node, the index of the scope enclosing it, and its nesting depth.
type Scope<'a> = (Node<'a>, Option<usize>, usize);

struct Resolver<'a> {
    text: &'a str,
    bindings: HashMap<(usize, &'a str), Option<Node<'a>>>,
    /// Every scope in the file, recorded by the walk so a lookup climbs scopes
    /// rather than calling `Node::parent`, which itself walks from the root.
    scopes: Vec<Scope<'a>>,
    /// The innermost scope around each identifier, by node id.
    scope_of: HashMap<usize, usize>,
    /// Module-level ESM import bindings: local name → the API it names
    /// (`exec` → `node:child_process.exec`, `cp` → `child_process`). Imports
    /// are immutable and hoisted, so one consulted only when no local binding
    /// shadows the name stays exact.
    imports: HashMap<&'a str, String>,
    /// Identifiers inside a `with` body, which may name any property of its
    /// object: they resolve to nothing.
    opaque: HashSet<usize>,
    /// [`Resolver::value`] steps left.
    fuel: Cell<u32>,
}

fn scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
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

impl<'a> Resolver<'a> {
    fn raw(&self, node: Node<'a>) -> Option<&'a str> {
        self.text.get(node.byte_range())
    }

    /// The scope a declaration inside `scope` binds into: the scope itself,
    /// or for a `var` or parameter the nearest function-level one.
    fn owner(&self, mut scope: usize, function_scoped: bool) -> Option<Node<'a>> {
        loop {
            let &(node, parent, _) = self.scopes.get(scope)?;
            match parent {
                Some(parent)
                    if function_scoped
                        && matches!(
                            node.kind(),
                            "statement_block"
                                | "catch_clause"
                                | "for_statement"
                                | "for_in_statement"
                        ) =>
                {
                    scope = parent;
                }
                _ => return Some(node),
            }
        }
    }

    /// The binding `name` refers to at identifier `node`.
    fn key(&self, node: Node<'a>, name: &'a str) -> Option<(usize, &'a str)> {
        let mut scope = self.scope_of.get(&node.id()).copied();
        while let Some(index) = scope {
            let &(owner, parent, _) = self.scopes.get(index)?;
            let key = (owner.id(), name);
            if self.bindings.contains_key(&key) {
                return Some(key);
            }
            scope = parent;
        }
        None
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
                    let mut cursor = node.walk();
                    nodes.extend(node.named_children(&mut cursor));
                    None
                }
            };
            if let Some((local, api)) = binding {
                // A name imported twice is ambiguous: resolve neither.
                self.imports
                    .entry(local)
                    .and_modify(String::clear)
                    .or_insert(api);
            }
        }
    }

    fn bind(&mut self, name: Node<'a>, value: Option<Node<'a>>, owner: Node<'a>) {
        // Destructuring is deliberately opaque, but its names still shadow.
        let mut nodes = vec![name];
        while let Some(node) = nodes.pop() {
            match node.kind() {
                "identifier" | "shorthand_property_identifier_pattern" => {
                    if let Some(raw) = self.raw(node) {
                        let key = (owner.id(), raw);
                        let v = if node.id() == name.id() { value } else { None };
                        self.bindings
                            .entry(key)
                            .and_modify(|old| *old = None)
                            .or_insert(v);
                    }
                }
                // A default value binds nothing; walking it would make nested
                // defaults (`f(a=function(a=function(…`) quadratic.
                "assignment_pattern" | "object_assignment_pattern" => {
                    nodes.extend(node.child_by_field_name("left"));
                }
                _ => {
                    let mut cursor = node.walk();
                    nodes.extend(node.named_children(&mut cursor));
                }
            }
        }
    }

    fn value(&self, node: Node<'a>, depth: usize) -> Option<Value> {
        self.fuel.set(self.fuel.get().checked_sub(1)?);
        if depth > 12 || node.end_byte() - node.start_byte() > VALUE_LIMIT {
            return None;
        }
        match node.kind() {
            "identifier" => {
                if self.opaque.contains(&node.id()) {
                    return None;
                }
                let name = self.raw(node)?;
                let Some(key) = self.key(node, name) else {
                    return self
                        .imports
                        .get(name)
                        .filter(|api| !api.is_empty())
                        .cloned()
                        .map(Value::Api);
                };
                let value = (*self.bindings.get(&key)?)?;
                // Reject forward references as well as cyclic initializers.
                if value.start_byte() >= node.start_byte() {
                    return None;
                }
                self.value(value, depth + 1)
            }
            "string" => {
                let raw = self.raw(node)?;
                let content = raw.get(1..raw.len().checked_sub(1)?)?;
                Some(Value::Text(
                    decode_escapes(content).unwrap_or_else(|| content.to_owned()),
                ))
            }
            "template_string" => {
                let mut value = String::new();
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    match child.kind() {
                        "string_fragment" | "escape_sequence" => value.push_str(
                            &decode_escapes(self.raw(child)?)
                                .unwrap_or_else(|| self.raw(child).unwrap_or_default().to_owned()),
                        ),
                        "template_substitution" => {
                            let Value::Text(part) = self.value(child.named_child(0)?, depth + 1)?
                            else {
                                return None;
                            };
                            value.push_str(&part);
                        }
                        _ => return None,
                    }
                    if value.len() > VALUE_LIMIT {
                        return None;
                    }
                }
                Some(Value::Text(value))
            }
            "binary_expression" if self.raw(node.child_by_field_name("operator")?)? == "+" => {
                let Value::Text(mut left) =
                    self.value(node.child_by_field_name("left")?, depth + 1)?
                else {
                    return None;
                };
                let Value::Text(right) =
                    self.value(node.child_by_field_name("right")?, depth + 1)?
                else {
                    return None;
                };
                if left.len() + right.len() > VALUE_LIMIT {
                    return None;
                }
                left.push_str(&right);
                Some(Value::Text(left))
            }
            "call_expression" => {
                let function = node.child_by_field_name("function")?;
                if self.raw(function)? != "require" || self.key(function, "require").is_some() {
                    return None;
                }
                let Value::Text(module) = self.value(
                    node.child_by_field_name("arguments")?.named_child(0)?,
                    depth + 1,
                )?
                else {
                    return None;
                };
                Some(Value::Api(module))
            }
            "member_expression" => {
                let Value::Api(module) =
                    self.value(node.child_by_field_name("object")?, depth + 1)?
                else {
                    return None;
                };
                Some(Value::Api(format!(
                    "{module}.{}",
                    self.raw(node.child_by_field_name("property")?)?
                )))
            }
            "parenthesized_expression" => self.value(node.named_child(0)?, depth + 1),
            _ => None,
        }
    }
}

pub(super) fn scan(parsed: &ParsedFile<'_>, out: &mut Found<'_>) {
    let Some(ast) = parsed.source_ast() else {
        return;
    };
    let mut resolver = Resolver {
        text: ast.source,
        bindings: HashMap::new(),
        scopes: Vec::new(),
        scope_of: HashMap::new(),
        imports: HashMap::new(),
        opaque: HashSet::new(),
        fuel: Cell::new(0),
    };
    // Each node with its innermost enclosing scope, its parent's kind, and
    // whether it sits in a `with` body.
    let mut stack: Vec<(Node<'_>, Option<usize>, &str, bool)> =
        vec![(ast.tree.root_node(), None, "", false)];
    let mut calls = Vec::new();
    let mut writes = Vec::new();
    let mut count = 0;
    while let Some((node, outer, parent, in_with)) = stack.pop() {
        count += 1;
        // A partial binding table could mistake a later write for a constant.
        if count > NODE_BUDGET {
            return;
        }
        let mut inner = outer;
        if scope(node) {
            let depth = outer
                .and_then(|o| resolver.scopes.get(o))
                .map_or(0, |&(_, _, depth)| depth + 1);
            if depth > MAX_SCOPE_DEPTH {
                tracing::debug!(depth, "js command resolution: scopes nested too deep");
                return;
            }
            resolver.scopes.push((node, outer, depth));
            inner = Some(resolver.scopes.len() - 1);
        }
        match node.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                if in_with {
                    resolver.opaque.insert(node.id());
                } else if let Some(scope) = outer {
                    resolver.scope_of.insert(node.id(), scope);
                }
            }
            "import_statement" => resolver.import(node),
            // Declared names shadow like any other binding; their values are
            // never commands.
            "function_declaration" | "generator_function_declaration" => {
                if let Some(name) = node.child_by_field_name("name")
                    && let Some(owner) = outer.and_then(|o| resolver.owner(o, true))
                {
                    resolver.bind(name, None, owner);
                }
            }
            "class_declaration" => {
                if let Some(name) = node.child_by_field_name("name")
                    && let Some(owner) = outer.and_then(|o| resolver.owner(o, false))
                {
                    resolver.bind(name, None, owner);
                }
            }
            // `for (const c of xs)` declares in the loop (a `var`, around it);
            // a bare `for (c of xs)` assigns.
            "for_in_statement" => {
                if let Some(left) = node.child_by_field_name("left") {
                    match node.child_by_field_name("kind") {
                        Some(kind) => {
                            let function_scoped = resolver.raw(kind) == Some("var");
                            if let Some(owner) =
                                inner.and_then(|i| resolver.owner(i, function_scoped))
                            {
                                resolver.bind(left, None, owner);
                            }
                        }
                        None => writes.push(left),
                    }
                }
            }
            "variable_declarator" => {
                if let Some(name) = node.child_by_field_name("name")
                    && let Some(owner) =
                        outer.and_then(|o| resolver.owner(o, parent == "variable_declaration"))
                {
                    resolver.bind(name, node.child_by_field_name("value"), owner);
                }
            }
            "formal_parameters" => {
                if let Some(owner) = outer.and_then(|o| resolver.owner(o, true)) {
                    resolver.bind(node, None, owner);
                }
            }
            "arrow_function" | "catch_clause" => {
                if let Some(parameter) = node.child_by_field_name("parameter") {
                    resolver.bind(parameter, None, node);
                }
            }
            "assignment_expression" | "augmented_assignment_expression" => {
                if let Some(left) = node.child_by_field_name("left") {
                    writes.push(left);
                }
            }
            "update_expression" => {
                if let Some(arg) = node.child_by_field_name("argument") {
                    writes.push(arg);
                }
            }
            "new_expression" | "call_expression" => calls.push(node),
            _ => {}
        }
        let kind = node.kind();
        // A `with` statement's object is evaluated normally; its body is not.
        let with_body = (kind == "with_statement")
            .then(|| node.child_by_field_name("body"))
            .flatten();
        let mut cursor = node.walk();
        stack.extend(
            node.named_children(&mut cursor)
                .map(|child| (child, inner, kind, in_with || with_body == Some(child))),
        );
    }
    // Every name a write can reach — destructuring included — is no longer a
    // constant. A member target writes a property, not a binding.
    let mut targets = writes;
    while let Some(node) = targets.pop() {
        match node.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                if let Some(name) = resolver.raw(node)
                    && let Some(key) = resolver.key(node, name)
                {
                    resolver.bindings.insert(key, None);
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
    let mut fuel = FILE_FUEL;
    let mut seen = HashSet::new();
    for node in calls {
        if fuel == 0 {
            tracing::debug!("js command resolution: file fuel exhausted");
            break;
        }
        let budget = CALL_FUEL.min(fuel);
        resolver.fuel.set(budget);
        let resolved = resolve_call(&resolver, node);
        fuel -= budget - resolver.fuel.get();
        let Some((shell, command)) = resolved else {
            continue;
        };
        // A command repeated at another call site yields the same references,
        // which the final dedup would drop: don't pay to scan it again.
        if !seen.insert(command.clone()) {
            continue;
        }
        let start = out.refs.len();
        commands(&command, None, "javascript", out);
        for reference in &mut out.refs[start..] {
            reference.source = if shell {
                "vscode-shell-execution"
            } else {
                "resolved-process-command"
            }
            .into();
            reference.offset = Some(node.start_byte() as u64);
            reference.evidence = clip(resolver.raw(node).unwrap_or(&command)).to_owned();
        }
    }
}

/// The shell command a process-execution call runs, when it resolves, and
/// whether the call is a VS Code `ShellExecution`.
fn resolve_call<'a>(resolver: &Resolver<'a>, node: Node<'a>) -> Option<(bool, String)> {
    let callee = node
        .child_by_field_name("constructor")
        .or_else(|| node.child_by_field_name("function"))?;
    let Value::Api(api) = resolver.value(callee, 0)? else {
        return None;
    };
    let shell = api == "vscode.ShellExecution";
    if !shell && !execution_call("javascript", &api) {
        return None;
    }
    let argument = node.child_by_field_name("arguments")?.named_child(0)?;
    let Value::Text(command) = resolver.value(argument, 0)? else {
        return None;
    };
    // Argument vectors need separate handling; do not reinterpret argv[0]
    // as a complete shell command.
    if matches!(
        api.rsplit('.').next(),
        Some("spawn" | "spawnSync" | "execFile" | "execFileSync")
    ) {
        return None;
    }
    Some((shell, command))
}

#[cfg(test)]
mod tests {
    use super::super::references_in_bytes;
    use filefacts::{RefKind, RefLocator};

    fn commands(source: &str) -> Vec<filefacts::Reference> {
        references_in_bytes(source.as_bytes(), "extension.js")
            .into_iter()
            .filter(|r| r.kind == RefKind::Command && r.source == "vscode-shell-execution")
            .collect()
    }

    #[test]
    fn resolves_pinned_constructor_command_with_lexical_bindings() {
        for declaration in ["const", "let", "var"] {
            let source = format!(
                r#"{declaration} api=require("vscode"),revision="abcdef0123456789";
                function install(){{let command=`npx -y github:example/tool#${{revision}}`,task=new api.Task({{}},1,"setup","x",new api.ShellExecution(command));}}
            "#
            );
            let refs = commands(&source);
            assert_eq!(refs.len(), 1);
            assert_eq!(
                refs[0].locator,
                RefLocator::Purl("pkg:github/example/tool@abcdef0123456789".into())
            );
            assert!(
                source[refs[0].offset.unwrap() as usize..].starts_with("new api.ShellExecution")
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
            assert!(commands(source).is_empty(), "{source}");
        }
    }

    #[test]
    fn renamed_https_and_concatenated_commands_are_followed() {
        let source = r#"const editor=require('vscode');const ref='fedcba';const command='npx --yes https://github.com/elsewhere/renamed#'+ref;new editor.ShellExecution(command);"#;
        assert_eq!(
            commands(source)[0].locator,
            RefLocator::Purl("pkg:github/elsewhere/renamed@fedcba".into())
        );
    }

    /// Every command reference, from any execution API.
    fn resolved(source: &str) -> Vec<String> {
        references_in_bytes(source.as_bytes(), "index.mjs")
            .into_iter()
            .filter(|r| r.source == "resolved-process-command")
            .filter_map(|r| match r.locator {
                RefLocator::Purl(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn esm_imports_of_child_process_are_followed() {
        for source in [
            "import {exec} from 'node:child_process'; const c='npm i evil'; exec(c);",
            "import {execSync as run} from 'child_process'; const c='npm i evil'; run(c);",
            "import * as cp from 'child_process'; const c='npm i evil'; cp.execSync(c);",
            "import cp from 'node:child_process'; const c='npm i evil'; cp.exec(c);",
        ] {
            assert_eq!(resolved(source), vec!["pkg:npm/evil"], "{source}");
        }
        // A local name shadows the import.
        assert!(
            resolved(
                "import {exec} from 'child_process'; function f(exec){const c='npm i evil'; exec(c)}"
            )
            .is_empty()
        );
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
            assert_eq!(resolved(&source), vec!["pkg:npm/ok"], "{source}");
        }
    }
}
