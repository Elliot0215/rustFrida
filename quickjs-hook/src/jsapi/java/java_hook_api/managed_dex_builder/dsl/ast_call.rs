use super::*;

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) struct DslCallStmt {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) kind: DslCallKind,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) target: Option<DslTarget>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) receiver: Option<Box<DslValue>>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) null_safe: bool,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) class_name: Option<String>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) method_name: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) sig: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) args: Vec<DslValue>,
}

impl DslCallStmt {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn class_label(&self) -> &str {
        self.class_name.as_deref().unwrap_or("<inferred>")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslCallKind {
    Virtual,
    Interface,
    Static,
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum ParsedCallArgs {
    Direct(Vec<DslValue>),
    ExplicitSignatureCall {
        class_name: Option<String>,
        sig: String,
        args: Vec<DslValue>,
    },
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) struct DslFieldStmt {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) target: Option<DslTarget>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) receiver: Option<Box<DslValue>>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) class_name: Option<String>,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) field_name: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) type_name: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) value: Option<DslValue>,
}
