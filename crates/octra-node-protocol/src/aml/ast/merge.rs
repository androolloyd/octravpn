// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Relocate imported syntax into one arena before native scope resolution.
use super::{Ast, ExprId, Interface, Nodes, Stmt, StmtId, Type, TypeId};
fn prepend<T>(target: &mut Vec<T>, mut imported: Vec<T>) {
    imported.append(target);
    *target = imported;
}
impl Ast {
    pub(crate) fn prepend_interfaces(&mut self, source: &Nodes, mut interfaces: Vec<Interface>) {
        let types = relocate_types(&mut self.nodes, source.types.iter().cloned());
        for interface in &mut interfaces {
            for method in &mut interface.methods {
                method.ret = types[method.ret.0];
                for param in &mut method.params {
                    param.typ = types[param.typ.0];
                }
            }
        }
        prepend(&mut self.contract.interfaces, interfaces);
    }
    pub(crate) fn prepend_import(&mut self, mut imported: Self) {
        let types = relocate_types(&mut self.nodes, imported.nodes.types);
        let type_id = |id: TypeId| types[id.0];
        let expr_base = self.nodes.expressions.len();
        let stmt_base = self.nodes.statements.len();
        let expr_id = |id: ExprId| ExprId(expr_base + id.0);
        let stmt_id = |id: StmtId| StmtId(stmt_base + id.0);
        for mut expr in imported.nodes.expressions {
            expr.map_exprs(&mut |id| expr_id(id));
            expr.map_types(&mut |id| type_id(id));
            self.nodes.expressions.push(expr);
        }
        for mut stmt in imported.nodes.statements {
            stmt.map_exprs(&mut |id| expr_id(id));
            match &mut stmt {
                Stmt::Located(_, _, inner) => *inner = stmt_id(*inner),
                Stmt::Let(_, Some(typ), _) => *typ = type_id(*typ),
                _ => (),
            }
            stmt.blocks(&mut |body| body.iter_mut().for_each(|id| *id = stmt_id(*id)));
            self.nodes.statements.push(stmt);
        }
        let root = &mut imported.contract;
        for structure in &mut root.structs {
            for (_, typ) in &mut structure.fields {
                *typ = type_id(*typ);
            }
        }
        for constant in &mut root.consts {
            constant.typ = type_id(constant.typ);
            constant.value = expr_id(constant.value);
        }
        for event in &mut root.events {
            for (_, typ, _) in &mut event.fields {
                *typ = type_id(*typ);
            }
        }
        for interface in &mut root.interfaces {
            for method in &mut interface.methods {
                method.ret = type_id(method.ret);
                for param in &mut method.params {
                    param.typ = type_id(param.typ);
                }
            }
        }
        for function in &mut root.functions {
            function.ret = type_id(function.ret);
            for param in &mut function.params {
                param.typ = type_id(param.typ);
            }
            for id in &mut function.body {
                *id = stmt_id(*id);
            }
        }
        for form in &mut root.forms {
            form.ret = type_id(form.ret);
            form.body = expr_id(form.body);
            for param in &mut form.params {
                param.typ = type_id(param.typ);
            }
        }
        prepend(
            &mut self.contract.structs,
            std::mem::take(&mut root.structs),
        );
        prepend(&mut self.contract.enums, std::mem::take(&mut root.enums));
        prepend(&mut self.contract.consts, std::mem::take(&mut root.consts));
        prepend(&mut self.contract.events, std::mem::take(&mut root.events));
        prepend(&mut self.contract.errors, std::mem::take(&mut root.errors));
        prepend(
            &mut self.contract.interfaces,
            std::mem::take(&mut root.interfaces),
        );
        prepend(
            &mut self.contract.functions,
            std::mem::take(&mut root.functions),
        );
        prepend(&mut self.contract.forms, std::mem::take(&mut root.forms));
    }
}
fn relocate_types(target: &mut Nodes, source: impl IntoIterator<Item = Type>) -> Vec<TypeId> {
    let mut types = vec![];
    for mut typ in source {
        let map = |id: &mut TypeId| *id = types[id.0];
        match &mut typ {
            Type::Map(key, value) => {
                map(key);
                map(value);
            }
            Type::List(value) | Type::Option(value) => map(value),
            Type::Tuple(values) => values.iter_mut().for_each(map),
            _ => (),
        }
        types.push(target.intern(typ));
    }
    types
}
