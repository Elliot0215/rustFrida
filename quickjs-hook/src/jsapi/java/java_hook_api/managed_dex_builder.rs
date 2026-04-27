use std::collections::{BTreeMap, BTreeSet};

use super::super::jni_core::JniEnv;
use super::super::reflect::{enumerate_methods, enumerate_methods_declared_only};

pub(super) const ACC_PUBLIC: u32 = 0x0001;
pub(super) const ACC_PRIVATE: u32 = 0x0002;
pub(super) const ACC_PROTECTED: u32 = 0x0004;
pub(super) const ACC_STATIC: u32 = 0x0008;
pub(super) const ACC_FINAL: u32 = 0x0010;
pub(super) const ACC_BRIDGE: u32 = 0x0040;
pub(super) const ACC_VOLATILE: u32 = 0x0040;
pub(super) const ACC_NATIVE: u32 = 0x0100;
pub(super) const ACC_SYNTHETIC: u32 = 0x1000;
pub(super) const ACC_CONSTRUCTOR: u32 = 0x0001_0000;
pub(super) const ACC_DECLARED_SYNCHRONIZED: u32 = 0x0002_0000;

const TYPE_HEADER_ITEM: u16 = 0x0000;
const TYPE_STRING_ID_ITEM: u16 = 0x0001;
const TYPE_TYPE_ID_ITEM: u16 = 0x0002;
const TYPE_PROTO_ID_ITEM: u16 = 0x0003;
const TYPE_FIELD_ID_ITEM: u16 = 0x0004;
const TYPE_METHOD_ID_ITEM: u16 = 0x0005;
const TYPE_CLASS_DEF_ITEM: u16 = 0x0006;
const TYPE_MAP_LIST: u16 = 0x1000;
const TYPE_TYPE_LIST: u16 = 0x1001;
const TYPE_CLASS_DATA_ITEM: u16 = 0x2000;
const TYPE_CODE_ITEM: u16 = 0x2001;
const TYPE_STRING_DATA_ITEM: u16 = 0x2002;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ProtoSpec {
    pub return_type: String,
    pub params: Vec<String>,
}

impl ProtoSpec {
    pub(super) fn new(return_type: impl Into<String>, params: Vec<String>) -> Self {
        Self {
            return_type: return_type.into(),
            params,
        }
    }

    fn shorty(&self) -> String {
        let mut out = String::with_capacity(self.params.len() + 1);
        out.push(shorty_char(&self.return_type));
        for param in &self.params {
            out.push(shorty_char(param));
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FieldRef {
    pub class_type: String,
    pub type_name: String,
    pub name: String,
}

impl FieldRef {
    pub(super) fn new(class_type: impl Into<String>, type_name: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            class_type: class_type.into(),
            type_name: type_name.into(),
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct MethodRef {
    pub class_type: String,
    pub proto: ProtoSpec,
    pub name: String,
}

impl MethodRef {
    pub(super) fn new(
        class_type: impl Into<String>,
        name: impl Into<String>,
        return_type: impl Into<String>,
        params: Vec<String>,
    ) -> Self {
        Self {
            class_type: class_type.into(),
            proto: ProtoSpec::new(return_type, params),
            name: name.into(),
        }
    }
}

mod dex_ir;
use dex_ir::{value_kind_from_descriptor, CodeWord, DexCode, DexIrBuilder, IfCmpOp, ValueKind};

#[derive(Clone, Debug)]
pub(super) struct ClassField {
    pub field: FieldRef,
    pub access_flags: u32,
}

#[derive(Clone, Debug)]
pub(super) struct ClassMethod {
    pub method: MethodRef,
    pub access_flags: u32,
    pub code: Option<DexCode>,
}

#[derive(Clone, Debug)]
pub(super) struct DexClass {
    pub class_type: String,
    pub access_flags: u32,
    pub super_type: String,
    pub source_file: Option<String>,
    pub static_fields: Vec<ClassField>,
    pub instance_fields: Vec<ClassField>,
    pub direct_methods: Vec<ClassMethod>,
    pub virtual_methods: Vec<ClassMethod>,
}

impl DexClass {
    pub(super) fn new(class_type: impl Into<String>) -> Self {
        Self {
            class_type: class_type.into(),
            access_flags: ACC_PUBLIC | ACC_FINAL,
            super_type: "Ljava/lang/Object;".to_string(),
            source_file: None,
            static_fields: Vec::new(),
            instance_fields: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
        }
    }

    pub(super) fn source_file(mut self, source_file: impl Into<String>) -> Self {
        self.source_file = Some(source_file.into());
        self
    }

    pub(super) fn static_field(&mut self, name: &str, type_name: &str, access_flags: u32) -> FieldRef {
        let field = FieldRef::new(self.class_type.clone(), type_name.to_string(), name.to_string());
        self.static_fields.push(ClassField {
            field: field.clone(),
            access_flags,
        });
        field
    }

    pub(super) fn direct_method(
        &mut self,
        name: &str,
        return_type: &str,
        params: Vec<String>,
        access_flags: u32,
        code: DexCode,
    ) -> MethodRef {
        let method = MethodRef::new(
            self.class_type.clone(),
            name.to_string(),
            return_type.to_string(),
            params,
        );
        self.direct_methods.push(ClassMethod {
            method: method.clone(),
            access_flags,
            code: Some(code),
        });
        method
    }

    pub(super) fn native_direct_method(
        &mut self,
        name: &str,
        return_type: &str,
        params: Vec<String>,
        access_flags: u32,
    ) -> MethodRef {
        let method = MethodRef::new(
            self.class_type.clone(),
            name.to_string(),
            return_type.to_string(),
            params,
        );
        self.direct_methods.push(ClassMethod {
            method: method.clone(),
            access_flags,
            code: None,
        });
        method
    }
}

pub(super) struct DexBuilder {
    classes: Vec<DexClass>,
    field_refs: BTreeSet<FieldRef>,
    method_refs: BTreeSet<MethodRef>,
}

impl DexBuilder {
    pub(super) fn new() -> Self {
        Self {
            classes: Vec::new(),
            field_refs: BTreeSet::new(),
            method_refs: BTreeSet::new(),
        }
    }

    pub(super) fn add_class(&mut self, class: DexClass) {
        self.classes.push(class);
    }

    pub(super) fn add_field_ref(&mut self, field: FieldRef) -> FieldRef {
        self.field_refs.insert(field.clone());
        field
    }

    pub(super) fn add_method_ref(&mut self, method: MethodRef) -> MethodRef {
        self.method_refs.insert(method.clone());
        method
    }

    pub(super) fn build(mut self) -> Result<Vec<u8>, String> {
        if self.classes.is_empty() {
            return Err("dex builder requires at least one class".to_string());
        }

        for class in &self.classes {
            for field in class.static_fields.iter().chain(class.instance_fields.iter()) {
                self.field_refs.insert(field.field.clone());
            }
            for method in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                self.method_refs.insert(method.method.clone());
                if let Some(code) = &method.code {
                    for word in &code.insns {
                        match word {
                            CodeWord::Field(field) => {
                                self.field_refs.insert(field.clone());
                            }
                            CodeWord::Method(method) => {
                                self.method_refs.insert(method.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let mut string_set = BTreeSet::<String>::new();
        let mut type_set = BTreeSet::<String>::new();
        let mut proto_set = BTreeSet::<ProtoSpec>::new();

        for class in &self.classes {
            type_set.insert(class.class_type.clone());
            type_set.insert(class.super_type.clone());
            if let Some(source_file) = &class.source_file {
                string_set.insert(source_file.clone());
            }
        }
        for field in &self.field_refs {
            type_set.insert(field.class_type.clone());
            type_set.insert(field.type_name.clone());
            string_set.insert(field.name.clone());
        }
        for method in &self.method_refs {
            type_set.insert(method.class_type.clone());
            type_set.insert(method.proto.return_type.clone());
            for param in &method.proto.params {
                type_set.insert(param.clone());
            }
            string_set.insert(method.name.clone());
            string_set.insert(method.proto.shorty());
            proto_set.insert(method.proto.clone());
        }
        for class in &self.classes {
            for method in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                if let Some(code) = &method.code {
                    for word in &code.insns {
                        match word {
                            CodeWord::String(value) => {
                                string_set.insert(value.clone());
                            }
                            CodeWord::Type(ty) => {
                                type_set.insert(ty.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        for ty in &type_set {
            string_set.insert(ty.clone());
        }

        let strings: Vec<String> = string_set.into_iter().collect();
        let string_idx: BTreeMap<String, u32> =
            strings.iter().enumerate().map(|(i, s)| (s.clone(), i as u32)).collect();

        let mut types: Vec<String> = type_set.into_iter().collect();
        types.sort_by_key(|ty| string_idx[ty]);
        let type_idx: BTreeMap<String, u32> = types.iter().enumerate().map(|(i, s)| (s.clone(), i as u32)).collect();

        let mut protos: Vec<ProtoSpec> = proto_set.into_iter().collect();
        protos.sort_by_key(|p| {
            (
                type_idx[&p.return_type],
                p.params.iter().map(|ty| type_idx[ty]).collect::<Vec<_>>(),
                string_idx[&p.shorty()],
            )
        });
        let proto_idx: BTreeMap<ProtoSpec, u32> =
            protos.iter().enumerate().map(|(i, p)| (p.clone(), i as u32)).collect();

        let mut fields: Vec<FieldRef> = self.field_refs.into_iter().collect();
        fields.sort_by_key(|f| (type_idx[&f.class_type], string_idx[&f.name], type_idx[&f.type_name]));
        let field_idx: BTreeMap<FieldRef, u32> =
            fields.iter().enumerate().map(|(i, f)| (f.clone(), i as u32)).collect();

        let mut methods: Vec<MethodRef> = self.method_refs.into_iter().collect();
        methods.sort_by_key(|m| (type_idx[&m.class_type], string_idx[&m.name], proto_idx[&m.proto]));
        let method_idx: BTreeMap<MethodRef, u32> =
            methods.iter().enumerate().map(|(i, m)| (m.clone(), i as u32)).collect();

        let mut type_lists = BTreeSet::<Vec<u32>>::new();
        for proto in &protos {
            if !proto.params.is_empty() {
                type_lists.insert(proto.params.iter().map(|p| type_idx[p]).collect());
            }
        }

        let header_size = 0x70usize;
        let string_ids_off = header_size;
        let type_ids_off = align4(string_ids_off + strings.len() * 4);
        let proto_ids_off = align4(type_ids_off + types.len() * 4);
        let field_ids_off = align4(proto_ids_off + protos.len() * 12);
        let method_ids_off = align4(field_ids_off + fields.len() * 8);
        let class_defs_off = align4(method_ids_off + methods.len() * 8);
        let data_off = align4(class_defs_off + self.classes.len() * 32);

        let mut data = Vec::new();
        let mut type_list_offsets = BTreeMap::<Vec<u32>, u32>::new();
        let first_type_list_off = if type_lists.is_empty() { 0 } else { data_off as u32 };
        for key in &type_lists {
            align_vec4(&mut data);
            let off = (data_off + data.len()) as u32;
            write_u32(&mut data, key.len() as u32);
            for idx in key {
                write_u16(&mut data, *idx as u16);
            }
            if key.len() % 2 != 0 {
                write_u16(&mut data, 0);
            }
            type_list_offsets.insert(key.clone(), off);
        }

        let first_string_data_off = (data_off + data.len()) as u32;
        let mut string_data_offsets = Vec::with_capacity(strings.len());
        for s in &strings {
            string_data_offsets.push((data_off + data.len()) as u32);
            write_uleb128(&mut data, s.chars().count() as u32);
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }

        let mut class_data_offsets = Vec::<u32>::with_capacity(self.classes.len());
        let mut code_patch_offsets = Vec::<(usize, DexCode)>::new();
        for class in &self.classes {
            align_vec4(&mut data);
            let class_data_off = (data_off + data.len()) as u32;
            class_data_offsets.push(class_data_off);
            write_class_data_item(&mut data, class, &field_idx, &method_idx, &mut code_patch_offsets)?;
        }

        let mut code_offsets = Vec::<u32>::new();
        for (patch_pos, code) in code_patch_offsets {
            align_vec4(&mut data);
            let code_off = (data_off + data.len()) as u32;
            data[patch_pos..patch_pos + 5].copy_from_slice(&uleb128_padded5(code_off));
            code_offsets.push(code_off);
            write_code_item(&mut data, &code, &string_idx, &type_idx, &field_idx, &method_idx)?;
        }

        align_vec4(&mut data);
        let map_off = (data_off + data.len()) as u32;
        write_map_list(
            &mut data,
            &[
                (TYPE_HEADER_ITEM, 1, 0),
                (TYPE_STRING_ID_ITEM, strings.len() as u32, string_ids_off as u32),
                (TYPE_TYPE_ID_ITEM, types.len() as u32, type_ids_off as u32),
                (TYPE_PROTO_ID_ITEM, protos.len() as u32, proto_ids_off as u32),
                (TYPE_FIELD_ID_ITEM, fields.len() as u32, field_ids_off as u32),
                (TYPE_METHOD_ID_ITEM, methods.len() as u32, method_ids_off as u32),
                (TYPE_CLASS_DEF_ITEM, self.classes.len() as u32, class_defs_off as u32),
                (TYPE_MAP_LIST, 1, map_off),
                (TYPE_TYPE_LIST, type_lists.len() as u32, first_type_list_off),
                (TYPE_CLASS_DATA_ITEM, self.classes.len() as u32, class_data_offsets[0]),
                (
                    TYPE_CODE_ITEM,
                    code_offsets.len() as u32,
                    code_offsets.first().copied().unwrap_or(0),
                ),
                (TYPE_STRING_DATA_ITEM, strings.len() as u32, first_string_data_off),
            ],
        );

        let file_size = data_off + data.len();
        let mut out = vec![0u8; data_off];
        out.extend_from_slice(&data);

        out[0..8].copy_from_slice(b"dex\n035\0");
        write_u32_at(&mut out, 32, file_size as u32);
        write_u32_at(&mut out, 36, header_size as u32);
        write_u32_at(&mut out, 40, 0x1234_5678);
        write_u32_at(&mut out, 52, map_off);
        write_u32_at(&mut out, 56, strings.len() as u32);
        write_u32_at(&mut out, 60, string_ids_off as u32);
        write_u32_at(&mut out, 64, types.len() as u32);
        write_u32_at(&mut out, 68, type_ids_off as u32);
        write_u32_at(&mut out, 72, protos.len() as u32);
        write_u32_at(&mut out, 76, proto_ids_off as u32);
        write_u32_at(&mut out, 80, fields.len() as u32);
        write_u32_at(&mut out, 84, field_ids_off as u32);
        write_u32_at(&mut out, 88, methods.len() as u32);
        write_u32_at(&mut out, 92, method_ids_off as u32);
        write_u32_at(&mut out, 96, self.classes.len() as u32);
        write_u32_at(&mut out, 100, class_defs_off as u32);
        write_u32_at(&mut out, 104, (file_size - data_off) as u32);
        write_u32_at(&mut out, 108, data_off as u32);

        for (i, off) in string_data_offsets.iter().enumerate() {
            write_u32_at(&mut out, string_ids_off + i * 4, *off);
        }
        for (i, ty) in types.iter().enumerate() {
            write_u32_at(&mut out, type_ids_off + i * 4, string_idx[ty]);
        }
        for (i, proto) in protos.iter().enumerate() {
            let params: Vec<u32> = proto.params.iter().map(|p| type_idx[p]).collect();
            let params_off = if params.is_empty() {
                0
            } else {
                type_list_offsets[&params]
            };
            let off = proto_ids_off + i * 12;
            write_u32_at(&mut out, off, string_idx[&proto.shorty()]);
            write_u32_at(&mut out, off + 4, type_idx[&proto.return_type]);
            write_u32_at(&mut out, off + 8, params_off);
        }
        for (i, field) in fields.iter().enumerate() {
            let off = field_ids_off + i * 8;
            write_u16_at(&mut out, off, type_idx[&field.class_type] as u16);
            write_u16_at(&mut out, off + 2, type_idx[&field.type_name] as u16);
            write_u32_at(&mut out, off + 4, string_idx[&field.name]);
        }
        for (i, method) in methods.iter().enumerate() {
            let off = method_ids_off + i * 8;
            write_u16_at(&mut out, off, type_idx[&method.class_type] as u16);
            write_u16_at(&mut out, off + 2, proto_idx[&method.proto] as u16);
            write_u32_at(&mut out, off + 4, string_idx[&method.name]);
        }

        for (i, class) in self.classes.iter().enumerate() {
            let off = class_defs_off + i * 32;
            write_u32_at(&mut out, off, type_idx[&class.class_type]);
            write_u32_at(&mut out, off + 4, class.access_flags);
            write_u32_at(&mut out, off + 8, type_idx[&class.super_type]);
            write_u32_at(&mut out, off + 12, 0);
            let source_idx = class.source_file.as_ref().map(|s| string_idx[s]).unwrap_or(0xffff_ffff);
            write_u32_at(&mut out, off + 16, source_idx);
            write_u32_at(&mut out, off + 20, 0);
            write_u32_at(&mut out, off + 24, class_data_offsets[i]);
            write_u32_at(&mut out, off + 28, 0);
        }

        let signature = sha1_digest(&out[32..]);
        out[12..32].copy_from_slice(&signature);
        let checksum = adler32(&out[12..]);
        write_u32_at(&mut out, 8, checksum);

        Ok(out)
    }
}

pub(super) struct GeneratedManagedDex {
    pub dex: Vec<u8>,
    pub class_name: String,
    pub method_name: String,
    pub method_sig: String,
    pub uses_orig: bool,
    pub string_literals: Vec<GeneratedStringLiteral>,
}

#[derive(Clone, Debug)]
pub(super) struct GeneratedStringLiteral {
    pub field_name: String,
    pub value: String,
}

mod descriptor;
use descriptor::{
    array_component_descriptor, build_method_sig, build_params_sig, descriptor_list_word_count,
    descriptor_to_java_class_name, descriptor_word_count, java_class_to_descriptor,
    java_class_to_descriptor_or_primitive, parse_call_params, parse_method_params_signature, parse_method_signature,
    return_is_object,
};

fn emit_return_from_orig(ir: &mut DexIrBuilder, return_type: &str) -> Result<(), String> {
    match return_type {
        "V" => ir.return_void(),
        "J" | "D" => {
            ir.move_result_wide(0);
            ir.return_wide(0);
        }
        ret if return_is_object(ret) => {
            ir.move_result_object(0);
            ir.return_object(0);
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            ir.move_result(0);
            ir.return_value(0);
        }
        other => return Err(format!("unsupported return type '{}'", other)),
    }
    Ok(())
}

mod semantic;
use semantic::validate_semantics;

fn resolve_call_proto(
    env: JniEnv,
    stmt: &DslCallStmt,
    class_type: &str,
) -> Result<(Vec<String>, String, String), String> {
    if let Ok((params, return_type)) = parse_method_signature(&stmt.sig) {
        return Ok((params, return_type, stmt.sig.clone()));
    }

    let params = parse_method_params_signature(&stmt.sig)?;
    let params_sig = build_params_sig(&params);
    let class_name = descriptor_to_java_class_name(class_type)?;
    let is_static = matches!(stmt.kind, DslCallKind::Static);
    let collect_matches = |declared_only: bool, include_synthetic: bool| -> Result<BTreeSet<String>, String> {
        let methods = unsafe {
            if declared_only {
                enumerate_methods_declared_only(env, &class_name)
            } else {
                enumerate_methods(env, &class_name)
            }
        }?;
        let mut matches = BTreeSet::new();
        for method in methods {
            if method.name != stmt.method_name || method.is_static != is_static {
                continue;
            }
            if !include_synthetic && (method.modifiers & (ACC_BRIDGE as i32 | ACC_SYNTHETIC as i32)) != 0 {
                continue;
            }
            let Ok((method_params, _)) = parse_method_signature(&method.sig) else {
                continue;
            };
            if build_params_sig(&method_params) == params_sig {
                matches.insert(method.sig);
            }
        }
        Ok(matches)
    };

    let declared_matches = collect_matches(true, false)?;
    let matches = if declared_matches.is_empty() {
        let inherited_matches = collect_matches(false, false)?;
        if inherited_matches.is_empty() {
            collect_matches(false, true)?
        } else {
            inherited_matches
        }
    } else {
        declared_matches
    };

    match matches.len() {
        1 => {
            let full_sig = matches.into_iter().next().unwrap();
            let (params, return_type) = parse_method_signature(&full_sig)?;
            Ok((params, return_type, full_sig))
        }
        0 => Err(format!(
            "method not found for {}.{}{}; use a full JNI signature if reflection cannot resolve it",
            class_name, stmt.method_name, params_sig
        )),
        _ => Err(format!(
            "ambiguous method return for {}.{}{}; use overload(\"full JNI signature\")",
            class_name, stmt.method_name, params_sig
        )),
    }
}

mod emitter;
use emitter::{
    collect_local_slots, emit_statements, helper_param_layout, program_max_invoke_words, program_uses_orig,
    validate_orig_bypass_flow, DslBuildContext, EmitContext, BASE_LOCAL_REG_COUNT,
};

pub(super) unsafe fn build_managed_dsl_dex(
    env: JniEnv,
    class_id: u64,
    target_class_name: &str,
    target_method_name: &str,
    target_sig: &str,
    is_static: bool,
    dsl: &str,
) -> Result<GeneratedManagedDex, String> {
    let program = parse_managed_dsl(dsl)?;
    let uses_orig = program_uses_orig(&program);
    if uses_orig {
        validate_orig_bypass_flow(&program)?;
    }
    let target_type = java_class_to_descriptor(target_class_name)?;
    let object_type = "Ljava/lang/Object;".to_string();
    let (target_params, return_type) = parse_method_signature(target_sig)?;
    validate_semantics(env, &program, is_static, target_type.clone(), target_params.clone())?;
    let mut helper_params = Vec::new();
    if !is_static {
        helper_params.push(target_type.clone());
    }
    helper_params.extend(target_params.clone());

    let ins_size = descriptor_list_word_count(&helper_params)?;
    if ins_size > u8::MAX as u16 {
        return Err(format!("too many invoke argument words: {}", ins_size));
    }
    let max_invoke_words = program_max_invoke_words(&program, &target_params, is_static)?;
    if max_invoke_words > u8::MAX as u16 {
        return Err(format!("too many DSL invoke argument words: {}", max_invoke_words));
    }
    let locals_start = BASE_LOCAL_REG_COUNT
        .checked_add(max_invoke_words)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let (local_slots, local_words) = collect_local_slots(&program, locals_start)?;
    let local_count = locals_start
        .checked_add(local_words)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let registers_size = local_count
        .checked_add(ins_size)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let outs_size = std::cmp::max(1u16, std::cmp::max(ins_size, max_invoke_words));
    if registers_size > u8::MAX as u16 {
        return Err(format!(
            "too many dex registers for generated helper: {}",
            registers_size
        ));
    }

    let generated_type = format!("Lrustfrida/DynManagedHook{};", class_id);
    let generated_class_name = format!("rustfrida.DynManagedHook{}", class_id);
    let sink = FieldRef::new(generated_type.clone(), object_type.clone(), "sink");
    let mut dsl_ctx = DslBuildContext::new(env, generated_type.clone(), BASE_LOCAL_REG_COUNT);
    let target = MethodRef::new(
        target_type.clone(),
        target_method_name.to_string(),
        return_type.clone(),
        target_params.clone(),
    );
    let mut ir = DexIrBuilder::new(registers_size, ins_size, outs_size);
    let layout = helper_param_layout(is_static, &target_type, &target_params, local_count, local_slots)?;
    let mut emit_ctx = EmitContext {
        layout: &layout,
        dsl_ctx: &mut dsl_ctx,
        is_static,
        local_count,
        ins_size,
        target: &target,
        return_type: &return_type,
        sink: &sink,
    };
    let saw_return = emit_statements(&mut ir, &program.stmts, &mut emit_ctx)?;
    if !saw_return {
        return Err("managed DSL must end with return statement".to_string());
    }
    let code = ir.finish()?;

    let mut class = DexClass::new(generated_type.clone()).source_file("RustFridaDynamicManagedHook.java");
    class.static_field("sink", &object_type, ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE);
    for lit in &dsl_ctx.string_literals {
        class.static_field(
            &lit.field_name,
            "Ljava/lang/String;",
            ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE,
        );
    }
    class.direct_method(
        "hook",
        &return_type,
        helper_params.clone(),
        ACC_PUBLIC | ACC_STATIC,
        code,
    );

    let mut builder = DexBuilder::new();
    builder.add_class(class);
    builder.add_method_ref(target);
    let dex = builder.build()?;

    Ok(GeneratedManagedDex {
        dex,
        class_name: generated_class_name,
        method_name: "hook".to_string(),
        method_sig: build_method_sig(&helper_params, &return_type),
        uses_orig,
        string_literals: dsl_ctx.string_literals,
    })
}

mod dsl;
use dsl::{parse_managed_dsl, DslCallKind, DslCallStmt};

fn write_class_data_item(
    out: &mut Vec<u8>,
    class: &DexClass,
    field_idx: &BTreeMap<FieldRef, u32>,
    method_idx: &BTreeMap<MethodRef, u32>,
    code_patch_offsets: &mut Vec<(usize, DexCode)>,
) -> Result<(), String> {
    write_uleb128(out, class.static_fields.len() as u32);
    write_uleb128(out, class.instance_fields.len() as u32);
    write_uleb128(out, class.direct_methods.len() as u32);
    write_uleb128(out, class.virtual_methods.len() as u32);

    write_encoded_fields(out, &class.static_fields, field_idx)?;
    write_encoded_fields(out, &class.instance_fields, field_idx)?;
    write_encoded_methods(out, &class.direct_methods, method_idx, code_patch_offsets)?;
    write_encoded_methods(out, &class.virtual_methods, method_idx, code_patch_offsets)?;
    Ok(())
}

fn write_encoded_fields(
    out: &mut Vec<u8>,
    fields: &[ClassField],
    field_idx: &BTreeMap<FieldRef, u32>,
) -> Result<(), String> {
    let mut entries = fields
        .iter()
        .map(|f| {
            let idx = *field_idx
                .get(&f.field)
                .ok_or_else(|| format!("missing field index for {}", f.field.name))?;
            Ok((idx, f.access_flags))
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by_key(|(idx, _)| *idx);

    let mut prev = 0u32;
    for (idx, access) in entries {
        write_uleb128(out, idx - prev);
        write_uleb128(out, access);
        prev = idx;
    }
    Ok(())
}

fn write_encoded_methods(
    out: &mut Vec<u8>,
    methods: &[ClassMethod],
    method_idx: &BTreeMap<MethodRef, u32>,
    code_patch_offsets: &mut Vec<(usize, DexCode)>,
) -> Result<(), String> {
    let mut entries = methods
        .iter()
        .map(|m| {
            let idx = *method_idx
                .get(&m.method)
                .ok_or_else(|| format!("missing method index for {}", m.method.name))?;
            Ok((idx, m.access_flags, m.code.clone()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by_key(|(idx, _, _)| *idx);

    let mut prev = 0u32;
    for (idx, access, code) in entries {
        write_uleb128(out, idx - prev);
        write_uleb128(out, access);
        if let Some(code) = code {
            let patch_pos = out.len();
            out.extend_from_slice(&[0, 0, 0, 0, 0]);
            code_patch_offsets.push((patch_pos, code));
        } else {
            write_uleb128(out, 0);
        }
        prev = idx;
    }
    Ok(())
}

fn write_code_item(
    out: &mut Vec<u8>,
    code: &DexCode,
    string_idx: &BTreeMap<String, u32>,
    type_idx: &BTreeMap<String, u32>,
    field_idx: &BTreeMap<FieldRef, u32>,
    method_idx: &BTreeMap<MethodRef, u32>,
) -> Result<(), String> {
    write_u16(out, code.registers_size);
    write_u16(out, code.ins_size);
    write_u16(out, code.outs_size);
    write_u16(out, 0);
    write_u32(out, 0);
    write_u32(out, code.insns.len() as u32);
    for word in &code.insns {
        match word {
            CodeWord::Raw(value) => write_u16(out, *value),
            CodeWord::String(value) => write_u16(out, lookup_u16(string_idx, value, "string")?),
            CodeWord::Type(ty) => write_u16(out, lookup_u16(type_idx, ty, "type")?),
            CodeWord::Field(field) => write_u16(out, lookup_u16(field_idx, field, "field")?),
            CodeWord::Method(method) => write_u16(out, lookup_u16(method_idx, method, "method")?),
        }
    }
    Ok(())
}

fn lookup_u16<K: Ord + std::fmt::Debug>(map: &BTreeMap<K, u32>, key: &K, kind: &str) -> Result<u16, String> {
    let value = *map
        .get(key)
        .ok_or_else(|| format!("missing {} index for {:?}", kind, key))?;
    if value > u16::MAX as u32 {
        return Err(format!("{} index too large: {}", kind, value));
    }
    Ok(value as u16)
}

fn shorty_char(descriptor: &str) -> char {
    match descriptor.as_bytes().first().copied() {
        Some(b'V') => 'V',
        Some(b'Z') => 'Z',
        Some(b'B') => 'B',
        Some(b'S') => 'S',
        Some(b'C') => 'C',
        Some(b'I') => 'I',
        Some(b'J') => 'J',
        Some(b'F') => 'F',
        Some(b'D') => 'D',
        _ => 'L',
    }
}

fn write_map_list(out: &mut Vec<u8>, entries: &[(u16, u32, u32)]) {
    let mut filtered: Vec<(u16, u32, u32)> = entries
        .iter()
        .copied()
        .filter(|(_, size, off)| *size != 0 || *off == 0)
        .collect();
    filtered.sort_by_key(|(_, _, off)| *off);
    write_u32(out, filtered.len() as u32);
    for (ty, size, off) in filtered {
        write_u16(out, ty);
        write_u16(out, 0);
        write_u32(out, size);
        write_u32(out, off);
    }
}

fn uleb128_padded5(mut value: u32) -> [u8; 5] {
    let mut out = [0u8; 5];
    let mut i = 0;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out[i] = byte;
        i += 1;
        if value == 0 {
            break;
        }
    }
    out
}

fn write_uleb128(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn align_vec4(out: &mut Vec<u8>) {
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u16_at(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_at(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in bytes {
        a = (a + *byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn sha1_digest(bytes: &[u8]) -> [u8; 20] {
    let mut h0 = 0x6745_2301u32;
    let mut h1 = 0xefcd_ab89u32;
    let mut h2 = 0x98ba_dcfeu32;
    let mut h3 = 0x1032_5476u32;
    let mut h4 = 0xc3d2_e1f0u32;

    let bit_len = (bytes.len() as u64) * 8;
    let mut msg = bytes.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            let off = i * 4;
            w[i] = u32::from_be_bytes([chunk[off], chunk[off + 1], chunk[off + 2], chunk[off + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}
