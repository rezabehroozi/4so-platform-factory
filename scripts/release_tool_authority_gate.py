#!/usr/bin/env python3
"""Fail closed when exact-release or C7W execution authority drifts across entrypoints."""
from __future__ import annotations

import argparse
import ast
import importlib.util
from pathlib import Path

AUTHORITY="RELEASE_TOOL_AUTHORITY_GATE_V1"
EXPECTED_RELEASE_BINARIES=(
    "platform-api","platformctl","platform-installer","platform-agent",
    "platform-probe","virtual-cluster-renderer","openchoreo-runtime","dapr-runtime",
)
EXPECTED_BUILD_TARGETS=(
    ("platform-api","./cmd/platform-api","1"),
    ("platformctl","./cmd/platformctl","0"),
    ("platform-installer","./cmd/platform-installer","0"),
    ("platform-agent","./cmd/platform-agent","0"),
    ("platform-probe","./cmd/platform-probe","0"),
    ("virtual-cluster-renderer","./cmd/virtual-cluster-renderer","0"),
    ("openchoreo-runtime","./cmd/openchoreo-runtime","0"),
    ("dapr-runtime","./cmd/dapr-runtime","0"),
)


def read_required(root:Path,rel:str,errors:list[tuple[str,str]])->str:
    path=root/rel
    if path.is_symlink() or not path.is_file():
        errors.append(("RELEASE_TOOL_AUTHORITY_FILE_MISSING",rel))
        return ""
    try:
        return path.read_text(encoding="utf-8",errors="strict")
    except (OSError,UnicodeDecodeError) as exc:
        errors.append(("RELEASE_TOOL_AUTHORITY_FILE_INVALID",f"{rel}:{exc}"))
        return ""


def literal_assignment(source:str,name:str):
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return None
    for node in tree.body:
        if isinstance(node,ast.Assign): targets=node.targets; value=node.value
        elif isinstance(node,ast.AnnAssign): targets=[node.target]; value=node.value
        else: continue
        if any(isinstance(target,ast.Name) and target.id==name for target in targets):
            try: return ast.literal_eval(value)
            except (ValueError,TypeError): return None
    return None


def direct_git_calls_without_env(source:str)->list[int]:
    def static_string(node):
        if isinstance(node,ast.Constant) and isinstance(node.value,str):
            return node.value
        if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Add):
            left=static_string(node.left); right=static_string(node.right)
            if left is not None and right is not None:
                return left+right
        return None
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return [0]
    missing=[]
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call) or not node.args:
            continue
        func=node.func
        command=node.args[0]
        if not (
            isinstance(func,ast.Attribute)
            and func.attr=="run"
            and isinstance(func.value,ast.Name)
            and func.value.id=="subprocess"
            and isinstance(command,(ast.List,ast.Tuple))
            and command.elts
            and static_string(command.elts[0])=="git"
        ):
            continue
        if not any(keyword.arg=="env" for keyword in node.keywords):
            missing.append(getattr(node,"lineno",0))
    return missing


def function_scope_nodes(function:ast.FunctionDef|ast.AsyncFunctionDef):
    """Walk definitely reachable runtime syntax without attributing dead/nested function bodies to the owner."""
    terminators=(ast.Return,ast.Raise,ast.Break,ast.Continue)

    def block_terminates(statements)->bool:
        for statement in statements:
            if isinstance(statement,terminators):
                return True
            if isinstance(statement,ast.If):
                if isinstance(statement.test,ast.Constant) and isinstance(statement.test.value,bool):
                    selected=statement.body if statement.test.value else statement.orelse
                    if block_terminates(selected):
                        return True
                elif statement.orelse and block_terminates(statement.body) and block_terminates(statement.orelse):
                    return True
        return False

    def visit_block(statements):
        for statement in statements:
            yield from visit(statement)
            if isinstance(statement,terminators):
                break
            if isinstance(statement,ast.If):
                if isinstance(statement.test,ast.Constant) and isinstance(statement.test.value,bool):
                    selected=statement.body if statement.test.value else statement.orelse
                    if block_terminates(selected):
                        break
                elif statement.orelse and block_terminates(statement.body) and block_terminates(statement.orelse):
                    break

    def visit(node):
        yield node
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node is not function:
            for decorator in node.decorator_list:
                yield from visit(decorator)
            for default in (*node.args.defaults,*node.args.kw_defaults):
                if default is not None:
                    yield from visit(default)
            if node.returns is not None:
                yield from visit(node.returns)
            return
        if isinstance(node,ast.Lambda):
            for default in (*node.args.defaults,*node.args.kw_defaults):
                if default is not None:
                    yield from visit(default)
            return
        if isinstance(node,ast.If):
            yield from visit(node.test)
            if isinstance(node.test,ast.Constant) and isinstance(node.test.value,bool):
                yield from visit_block(node.body if node.test.value else node.orelse)
            else:
                yield from visit_block(node.body)
                yield from visit_block(node.orelse)
            return
        if isinstance(node,ast.While) and isinstance(node.test,ast.Constant) and node.test.value is False:
            yield from visit(node.test)
            yield from visit_block(node.orelse)
            return
        for child in ast.iter_child_nodes(node):
            yield from visit(child)

    yield from visit_block(function.body)


def function_call_lines(source:str,function_name:str)->dict[str,int]:
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return {}
    fn=next((node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name==function_name),None)
    if fn is None:
        return {}
    calls:dict[str,int]={}
    for node in function_scope_nodes(fn):
        if not isinstance(node,ast.Call):
            continue
        name=""
        if isinstance(node.func,ast.Name):
            name=node.func.id
        elif isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name):
            name=f"{node.func.value.id}.{node.func.attr}"
        if name:
            calls[name]=min(calls.get(name,node.lineno),node.lineno)
    return calls


def ordered_calls(calls:dict[str,int],names:tuple[str,...])->bool:
    if any(name not in calls for name in names):
        return False
    return all(calls[left]<calls[right] for left,right in zip(names,names[1:]))


def ordered_calls_on_same_path(source:str,function_name:str,names:tuple[str,...])->bool:
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return False
    function=next((node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name==function_name),None)
    if function is None or not names or len(set(names))!=len(names):
        return False
    positions={name:index for index,name in enumerate(names)}
    invalid=False
    completed=False

    def call_name(node:ast.Call)->str:
        if isinstance(node.func,ast.Name):
            return node.func.id
        if isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        return ""

    def calls_in_eval_order(node)->list[str]:
        if node is None or isinstance(node,(ast.Lambda,ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
            return []
        calls=[]
        if isinstance(node,ast.Call):
            calls.extend(calls_in_eval_order(node.func))
            for arg in node.args:
                calls.extend(calls_in_eval_order(arg))
            for keyword in node.keywords:
                calls.extend(calls_in_eval_order(keyword.value))
            name=call_name(node)
            if name:
                calls.append(name)
            return calls
        for child in ast.iter_child_nodes(node):
            calls.extend(calls_in_eval_order(child))
        return calls

    def contains_target_call(node)->bool:
        return any(name in positions for name in calls_in_eval_order(node))

    def has_conditional_target_call(node)->bool:
        if node is None:
            return False
        for candidate in ast.walk(node):
            if isinstance(candidate,ast.BoolOp):
                if any(contains_target_call(value) for value in candidate.values[1:]):
                    return True
            elif isinstance(candidate,ast.IfExp):
                if contains_target_call(candidate.body) or contains_target_call(candidate.orelse):
                    return True
            elif isinstance(candidate,ast.Compare) and len(candidate.ops)>1:
                if any(contains_target_call(value) for value in candidate.comparators[1:]):
                    return True
            elif isinstance(candidate,(ast.ListComp,ast.SetComp,ast.DictComp,ast.GeneratorExp)):
                if contains_target_call(candidate):
                    return True
        return False

    def advance(state:int,node)->int:
        nonlocal invalid,completed
        if has_conditional_target_call(node):
            invalid=True
        for name in calls_in_eval_order(node):
            index=positions.get(name)
            if index is None:
                continue
            if index>state:
                invalid=True
                continue
            if index==state:
                state+=1
                if state==len(names):
                    completed=True
        return state

    def process_block(statements,states:set[int])->set[int]:
        live=set(states)
        for statement in statements:
            if not live:
                break
            next_live=set()
            for state in live:
                next_live.update(process_statement(statement,state))
            live=next_live
        return live

    def process_statement(statement,state:int)->set[int]:
        nonlocal invalid
        if isinstance(statement,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
            return {state}
        if isinstance(statement,ast.If):
            state=advance(state,statement.test)
            if isinstance(statement.test,ast.Constant) and isinstance(statement.test.value,bool):
                selected=statement.body if statement.test.value else statement.orelse
                return process_block(selected,{state})
            body_states=process_block(statement.body,{state})
            else_states=process_block(statement.orelse,{state}) if statement.orelse else {state}
            return body_states|else_states
        if isinstance(statement,ast.Match):
            state=advance(state,statement.subject)
            live=set()
            exhaustive=False
            for case in statement.cases:
                if case.guard is not None and contains_target_call(case.guard):
                    invalid=True
                live.update(process_block(case.body,{state}))
                if isinstance(case.pattern,ast.MatchAs) and case.pattern.pattern is None and case.guard is None:
                    exhaustive=True
            if not exhaustive:
                live.add(state)
            return live
        if isinstance(statement,(ast.Return,ast.Raise)):
            value=statement.value if isinstance(statement,ast.Return) else statement.exc
            advance(state,value)
            return set()
        if isinstance(statement,(ast.With,ast.AsyncWith)):
            for item in statement.items:
                state=advance(state,item.context_expr)
            return process_block(statement.body,{state})
        if isinstance(statement,ast.Try):
            normal=process_block(statement.body,{state})
            if statement.orelse:
                normal=process_block(statement.orelse,normal)
            handler_states=set()
            for handler in statement.handlers:
                handler_state=advance(state,handler.type)
                handler_states.update(process_block(handler.body,{handler_state}))
            live=normal|handler_states
            if statement.finalbody:
                live=process_block(statement.finalbody,live)
            return live
        if isinstance(statement,(ast.For,ast.AsyncFor,ast.While)):
            if any(name in positions for name in calls_in_eval_order(statement)):
                invalid=True
            return {state}
        if isinstance(statement,ast.Assign):
            return {advance(state,statement.value)}
        if isinstance(statement,ast.AnnAssign):
            return {advance(state,statement.value)}
        if isinstance(statement,ast.AugAssign):
            return {advance(state,statement.value)}
        if isinstance(statement,ast.Expr):
            return {advance(state,statement.value)}
        if isinstance(statement,ast.Assert):
            state=advance(state,statement.test)
            return {advance(state,statement.msg)}
        return {advance(state,statement)}

    live=process_block(function.body,{0})
    return not invalid and completed and all(state==len(names) for state in live)


def assignment_targets_and_value(node):
    if isinstance(node,ast.Assign):
        return list(node.targets),node.value
    if isinstance(node,ast.AnnAssign):
        return [node.target],node.value
    if isinstance(node,ast.AugAssign):
        return [node.target],None
    if isinstance(node,ast.NamedExpr):
        return [node.target],node.value
    if isinstance(node,ast.Delete):
        return list(node.targets),None
    if isinstance(node,(ast.For,ast.AsyncFor)):
        return [node.target],node.iter
    if isinstance(node,ast.comprehension):
        return [node.target],node.iter
    if isinstance(node,(ast.With,ast.AsyncWith)):
        return [item.optional_vars for item in node.items if item.optional_vars is not None],None
    if isinstance(node,ast.ExceptHandler) and node.name:
        return [ast.Name(id=node.name,ctx=ast.Store())],None
    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
        return [ast.Name(id=node.name,ctx=ast.Store())],None
    if isinstance(node,(ast.Import,ast.ImportFrom)):
        return [ast.Name(id=(alias.asname or alias.name.split(".",1)[0]),ctx=ast.Store()) for alias in node.names],None
    if isinstance(node,ast.Match):
        targets=[]
        def pattern_bound_names(pattern):
            bound=[]
            for candidate in ast.walk(pattern):
                name=None
                if isinstance(candidate,ast.MatchAs):
                    name=candidate.name
                elif isinstance(candidate,ast.MatchStar):
                    name=candidate.name
                elif isinstance(candidate,ast.MatchMapping):
                    name=candidate.rest
                if name:
                    bound.append(ast.Name(id=name,ctx=ast.Store()))
            return bound
        for case in node.cases:
            targets.extend(pattern_bound_names(case.pattern))
        return targets,node.subject
    if isinstance(node,ast.MatchAs) and node.name:
        return [ast.Name(id=node.name,ctx=ast.Store())],None
    return [],None


def assignment_target_nodes(target):
    yield target
    if isinstance(target,(ast.Tuple,ast.List)):
        for element in target.elts:
            yield from assignment_target_nodes(element)


def direct_authority_alias_present(function:ast.FunctionDef|ast.AsyncFunctionDef,owner:str)->bool:
    for node in function_scope_nodes(function):
        targets,value=assignment_targets_and_value(node)
        if not c9_direct_authority_exposure(value,owner):
            continue
        for root_target in targets:
            for target in assignment_target_nodes(root_target):
                if isinstance(target,(ast.Tuple,ast.List)):
                    continue
                if isinstance(target,ast.Name) and target.id==owner:
                    continue
                return True
    return False


def c9_target_base_name(target)->str|None:
    while isinstance(target,(ast.Attribute,ast.Subscript)):
        target=target.value
    return target.id if isinstance(target,ast.Name) else None


def c9_root_value_valid(value)->bool:
    return (
        isinstance(value,ast.Call)
        and isinstance(value.func,ast.Attribute)
        and value.func.attr=="resolve"
        and not value.args
        and isinstance(value.func.value,ast.Attribute)
        and value.func.value.attr=="root"
        and isinstance(value.func.value.value,ast.Name)
        and value.func.value.value.id=="args"
    )


def c9_working_directory_value_valid(value)->bool:
    return (
        isinstance(value,ast.Call)
        and isinstance(value.func,ast.Name)
        and value.func.id=="str"
        and len(value.args)==1
        and isinstance(value.args[0],ast.Name)
        and value.args[0].id=="root"
    )


def c9_output_value_valid(value)->bool:
    return (
        isinstance(value,ast.Call)
        and isinstance(value.func,ast.Name)
        and value.func.id=="canonical_cli_output_path"
        and len(value.args)==2
        and isinstance(value.args[0],ast.Name)
        and value.args[0].id=="root"
        and isinstance(value.args[1],ast.Attribute)
        and value.args[1].attr=="out"
        and isinstance(value.args[1].value,ast.Name)
        and value.args[1].value.id=="args"
    )


def c9_evidence_value_valid(value)->bool:
    return (
        isinstance(value,ast.Call)
        and isinstance(value.func,ast.Name)
        and value.func.id=="execute"
        and len(value.args)>=2
        and isinstance(value.args[0],ast.Name)
        and value.args[0].id=="root"
        and isinstance(value.args[1],ast.Name)
        and value.args[1].id=="out"
    )


def c9_args_attribute_call_mutation(node)->str|None:
    if not isinstance(node,ast.Call):
        return None
    func=node.func
    if isinstance(func,ast.Name) and func.id in ("setattr","delattr") and len(node.args)>=2:
        owner,name=node.args[:2]
        if isinstance(owner,ast.Name) and owner.id=="args" and isinstance(name,ast.Constant) and isinstance(name.value,str):
            return name.value
    if isinstance(func,ast.Attribute) and isinstance(func.value,ast.Name) and func.value.id=="args" and func.attr in ("__setattr__","__delattr__") and node.args:
        name=node.args[0]
        if isinstance(name,ast.Constant) and isinstance(name.value,str):
            return name.value
    return None


def c9_mapping_mutation_call(node,owner:str)->bool:
    return (
        isinstance(node,ast.Call)
        and isinstance(node.func,ast.Attribute)
        and isinstance(node.func.value,ast.Name)
        and node.func.value.id==owner
        and node.func.attr in ("update","clear","pop","popitem","setdefault","__setitem__","__delitem__")
    )


def c9_parser_args_value_valid(value)->bool:
    return (
        isinstance(value,ast.Call)
        and isinstance(value.func,ast.Attribute)
        and value.func.attr=="parse_args"
        and isinstance(value.func.value,ast.Name)
        and value.func.value.id=="parser"
    )


def c9_mutable_args_mapping_alias_value(value)->bool:
    if (
        isinstance(value,ast.Attribute)
        and value.attr=="__dict__"
        and isinstance(value.value,ast.Name)
        and value.value.id=="args"
    ):
        return True
    return (
        isinstance(value,ast.Call)
        and isinstance(value.func,ast.Name)
        and value.func.id=="vars"
        and len(value.args)==1
        and isinstance(value.args[0],ast.Name)
        and value.args[0].id=="args"
    )


def c9_call_name(node)->str:
    if not isinstance(node,ast.Call):
        return ""
    if isinstance(node.func,ast.Name):
        return node.func.id
    if isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name):
        return f"{node.func.value.id}.{node.func.attr}"
    return ""


def c9_direct_authority_exposure(value,owner:str)->bool:
    if isinstance(value,ast.Name) and value.id==owner:
        return True
    if owner=="args" and c9_mutable_args_mapping_alias_value(value):
        return True
    if isinstance(value,ast.Attribute):
        receiver=value.value
        if owner!="args" and c9_direct_authority_exposure(receiver,owner):
            return True
        if owner=="args" and c9_mutable_args_mapping_alias_value(receiver):
            return True
        if (
            isinstance(receiver,ast.Name)
            and receiver.id==owner
            and value.attr in ("update","clear","pop","popitem","setdefault","__setitem__","__delitem__","__setattr__","__delattr__")
        ):
            return True
    if isinstance(value,(ast.Tuple,ast.List,ast.Set)):
        return any(c9_direct_authority_exposure(item,owner) for item in value.elts)
    if isinstance(value,ast.Dict):
        return any(
            c9_direct_authority_exposure(item,owner)
            for item in [*value.keys,*value.values]
            if item is not None
        )
    if isinstance(value,ast.Starred):
        return c9_direct_authority_exposure(value.value,owner)
    if isinstance(value,ast.IfExp):
        return c9_direct_authority_exposure(value.body,owner) or c9_direct_authority_exposure(value.orelse,owner)
    if isinstance(value,ast.BoolOp):
        return any(c9_direct_authority_exposure(item,owner) for item in value.values)
    if isinstance(value,ast.BinOp):
        return c9_direct_authority_exposure(value.left,owner) or c9_direct_authority_exposure(value.right,owner)
    if isinstance(value,(ast.ListComp,ast.SetComp,ast.GeneratorExp)):
        return c9_direct_authority_exposure(value.elt,owner)
    if isinstance(value,ast.DictComp):
        return c9_direct_authority_exposure(value.key,owner) or c9_direct_authority_exposure(value.value,owner)
    if isinstance(value,ast.Subscript):
        container=value.value
        try:
            index=ast.literal_eval(value.slice)
        except (ValueError,TypeError,SyntaxError):
            return c9_direct_authority_exposure(container,owner)
        if isinstance(container,(ast.Tuple,ast.List)) and isinstance(index,int):
            try:
                return c9_direct_authority_exposure(container.elts[index],owner)
            except IndexError:
                return False
        if isinstance(container,ast.Dict):
            for key,item in reversed(list(zip(container.keys,container.values))):
                try:
                    matches=ast.literal_eval(key)==index
                except (ValueError,TypeError,SyntaxError):
                    continue
                if matches:
                    return c9_direct_authority_exposure(item,owner)
    return False


def c9_default_authority_capture_present(function:ast.FunctionDef|ast.AsyncFunctionDef,owner:str)->bool:
    for node in function_scope_nodes(function):
        if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.Lambda)) or node is function:
            continue
        defaults=(*node.args.defaults,*node.args.kw_defaults)
        if any(default is not None and c9_direct_authority_exposure(default,owner) for default in defaults):
            return True
    return False


def c9_nested_scope_closure_capture(node,owner:str)->bool:
    params={arg.arg for arg in (*node.args.posonlyargs,*node.args.args,*node.args.kwonlyargs)}
    if node.args.vararg is not None:
        params.add(node.args.vararg.arg)
    if node.args.kwarg is not None:
        params.add(node.args.kwarg.arg)
    if owner in params:
        return False
    local_bound=False
    global_declared=False
    nonlocal_declared=False
    loaded=False
    roots=[node.body] if isinstance(node,ast.Lambda) else list(node.body)
    stack=list(roots)
    while stack:
        current=stack.pop()
        if isinstance(current,(ast.FunctionDef,ast.AsyncFunctionDef,ast.Lambda,ast.ClassDef)):
            continue
        if isinstance(current,ast.Global) and owner in current.names:
            global_declared=True
        elif isinstance(current,ast.Nonlocal) and owner in current.names:
            nonlocal_declared=True
        elif isinstance(current,ast.Name) and current.id==owner:
            if isinstance(current.ctx,ast.Load):
                loaded=True
            elif isinstance(current.ctx,(ast.Store,ast.Del)):
                local_bound=True
        stack.extend(ast.iter_child_nodes(current))
    if nonlocal_declared:
        return True
    return loaded and not local_bound and not global_declared


def c9_closure_authority_capture_present(function:ast.FunctionDef|ast.AsyncFunctionDef,owner:str)->bool:
    for node in function_scope_nodes(function):
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.Lambda)) and node is not function:
            if c9_nested_scope_closure_capture(node,owner):
                return True
    return False


def c9_unknown_authority_helper_call(node,owner:str,allowed:tuple[str,...]=())->bool:
    if not isinstance(node,ast.Call) or c9_call_name(node) in set(allowed):
        return False
    receiver=node.func.value if isinstance(node.func,ast.Attribute) else None
    return (
        c9_direct_authority_exposure(receiver,owner)
        or any(c9_direct_authority_exposure(arg,owner) for arg in node.args)
        or any(c9_direct_authority_exposure(keyword.value,owner) for keyword in node.keywords)
    )


def c9_cli_args_authority_mutated(function:ast.FunctionDef|ast.AsyncFunctionDef)->bool:
    if direct_authority_alias_present(function,"args") or c9_default_authority_capture_present(function,"args") or c9_closure_authority_capture_present(function,"args"):
        return True
    parser_binding_seen=False
    mutators=("update","clear","pop","popitem","setdefault","__setitem__","__delitem__","__setattr__","__delattr__")
    for node in function_scope_nodes(function):
        targets,value=assignment_targets_and_value(node)
        flat_targets=[item for root_target in targets for item in assignment_target_nodes(root_target)]
        if c9_mutable_args_mapping_alias_value(value) and any(
            isinstance(target,ast.Name) and target.id!="args" for target in flat_targets
        ):
            return True
        for target in flat_targets:
            if isinstance(target,ast.Name) and target.id=="args":
                if not parser_binding_seen and c9_parser_args_value_valid(value):
                    parser_binding_seen=True
                    continue
                return True
            if c9_target_base_name(target)=="args":
                return True
        if c9_args_attribute_call_mutation(node) is not None:
            return True
        if c9_unknown_authority_helper_call(node,"args"):
            return True
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr in mutators:
            owner=node.func.value
            if c9_target_base_name(owner)=="args":
                return True
            if (
                isinstance(owner,ast.Call)
                and isinstance(owner.func,ast.Name)
                and owner.func.id=="vars"
                and len(owner.args)==1
                and isinstance(owner.args[0],ast.Name)
                and owner.args[0].id=="args"
            ):
                return True
    return False


def c9_main_working_directory_bound(source:str)->bool:
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return False
    main=next((node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="main"),None)
    if main is None or c9_cli_args_authority_mutated(main) or c9_default_authority_capture_present(main,"result") or c9_closure_authority_capture_present(main,"result"):
        return False
    root_valid=False
    root_line=None
    working_valid=False
    working_line=None
    for node in main.body:
        if isinstance(node,(ast.Return,ast.Raise)):
            break
        targets,value=assignment_targets_and_value(node)
        flat_targets=[item for root_target in targets for item in assignment_target_nodes(root_target)]
        for target in flat_targets:
            if isinstance(target,ast.Name) and target.id=="root":
                direct_target=len(targets)==1 and targets[0] is target and not isinstance(node,ast.AugAssign)
                root_valid=direct_target and c9_root_value_valid(value)
                root_line=getattr(node,"lineno",0) if root_valid else None
                working_valid=False
                working_line=None
            elif isinstance(target,ast.Name) and target.id=="result":
                working_valid=False
                working_line=None
            elif (
                isinstance(target,ast.Subscript)
                and isinstance(target.value,ast.Name)
                and target.value.id=="result"
                and isinstance(target.slice,ast.Constant)
                and target.slice.value=="workingDirectory"
            ):
                direct_target=len(targets)==1 and targets[0] is target and not isinstance(node,ast.AugAssign)
                working_valid=direct_target and root_valid and c9_working_directory_value_valid(value)
                working_line=getattr(node,"lineno",0) if working_valid else None
    if root_valid and working_valid and root_line is not None and working_line is not None:
        for node in function_scope_nodes(main):
            line=getattr(node,"lineno",0)
            if line<=root_line or line>=working_line:
                continue
            targets,_=assignment_targets_and_value(node)
            if any(c9_target_base_name(target)=="root" for root_target in targets for target in assignment_target_nodes(root_target)):
                root_valid=False
                working_valid=False
    if working_valid and working_line is not None:
        for node in function_scope_nodes(main):
            if getattr(node,"lineno",0)<=working_line:
                continue
            targets,_=assignment_targets_and_value(node)
            for target in (item for root_target in targets for item in assignment_target_nodes(root_target)):
                if c9_target_base_name(target)=="root":
                    root_valid=False
                    working_valid=False
                elif isinstance(target,ast.Name) and target.id=="result":
                    working_valid=False
                elif (
                    isinstance(target,ast.Subscript)
                    and isinstance(target.value,ast.Name)
                    and target.value.id=="result"
                    and isinstance(target.slice,ast.Constant)
                    and target.slice.value=="workingDirectory"
                ):
                    working_valid=False
            if c9_args_attribute_call_mutation(node)=="root":
                root_valid=False
                working_valid=False
            if c9_mapping_mutation_call(node,"result"):
                working_valid=False
            if c9_unknown_authority_helper_call(node,"result",("json.dumps",)):
                working_valid=False
    if direct_authority_alias_present(main,"result") or c9_default_authority_capture_present(main,"result") or c9_closure_authority_capture_present(main,"result"):
        working_valid=False
    return root_valid and working_valid


def c9_main_canonical_output_bound(source:str)->bool:
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return False
    main=next((node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="main"),None)
    if main is None or c9_cli_args_authority_mutated(main) or c9_default_authority_capture_present(main,"evidence") or c9_closure_authority_capture_present(main,"evidence"):
        return False
    root_valid=False
    root_line=None
    out_valid=False
    out_line=None
    evidence_valid=False
    evidence_line=None
    for node in main.body:
        if isinstance(node,(ast.Return,ast.Raise)):
            break
        targets,value=assignment_targets_and_value(node)
        flat_targets=[item for root_target in targets for item in assignment_target_nodes(root_target)]
        for target in flat_targets:
            if not isinstance(target,ast.Name):
                continue
            direct_target=len(targets)==1 and targets[0] is target and not isinstance(node,ast.AugAssign)
            if target.id=="root":
                root_valid=direct_target and c9_root_value_valid(value)
                root_line=getattr(node,"lineno",0) if root_valid else None
                out_valid=False
                out_line=None
                evidence_valid=False
                evidence_line=None
            elif target.id=="out":
                out_valid=direct_target and root_valid and c9_output_value_valid(value)
                out_line=getattr(node,"lineno",0) if out_valid else None
                evidence_valid=False
                evidence_line=None
            elif target.id=="evidence":
                evidence_valid=direct_target and root_valid and out_valid and c9_evidence_value_valid(value)
                evidence_line=getattr(node,"lineno",0) if evidence_valid else None
    if evidence_valid and evidence_line is not None:
        for node in function_scope_nodes(main):
            line=getattr(node,"lineno",0)
            if root_line is not None and root_line<line<evidence_line:
                targets,_=assignment_targets_and_value(node)
                if any(c9_target_base_name(target)=="root" for root_target in targets for target in assignment_target_nodes(root_target)):
                    root_valid=False
                    out_valid=False
                    evidence_valid=False
            if out_line is not None and out_line<line<evidence_line:
                targets,_=assignment_targets_and_value(node)
                if any(c9_target_base_name(target)=="out" for root_target in targets for target in assignment_target_nodes(root_target)):
                    out_valid=False
                    evidence_valid=False
    if evidence_valid and evidence_line is not None:
        for node in function_scope_nodes(main):
            if getattr(node,"lineno",0)<=evidence_line:
                continue
            targets,_=assignment_targets_and_value(node)
            for target in (item for root_target in targets for item in assignment_target_nodes(root_target)):
                base=c9_target_base_name(target)
                if base=="root":
                    root_valid=False
                    out_valid=False
                    evidence_valid=False
                elif base=="out":
                    out_valid=False
                    evidence_valid=False
                elif base=="evidence":
                    evidence_valid=False
            mutation=c9_args_attribute_call_mutation(node)
            if mutation=="root":
                root_valid=False
                out_valid=False
                evidence_valid=False
            elif mutation=="out":
                out_valid=False
                evidence_valid=False
            if c9_mapping_mutation_call(node,"evidence"):
                evidence_valid=False
            if c9_unknown_authority_helper_call(node,"evidence",("final_git_handoff",)):
                evidence_valid=False
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="execute":
                evidence_valid=False
    if direct_authority_alias_present(main,"evidence") or c9_default_authority_capture_present(main,"evidence") or c9_closure_authority_capture_present(main,"evidence"):
        evidence_valid=False
    return root_valid and out_valid and evidence_valid


def c7w_execution_errors(root:Path)->list[tuple[str,str]]:
    gate=root/"scripts/c7w_execution_authority_gate.py"
    if gate.is_symlink() or not gate.is_file():
        return [("C7W_EXECUTION_AUTHORITY_GATE_MISSING","scripts/c7w_execution_authority_gate.py")]
    spec=importlib.util.spec_from_file_location("c7w_execution_authority_gate_release",gate)
    if spec is None or spec.loader is None:
        return [("C7W_EXECUTION_AUTHORITY_GATE_INVALID","module spec unavailable")]
    module=importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        return [("C7W_EXECUTION_AUTHORITY_GATE_INVALID",str(exc))]
    validate=getattr(module,"validate",None)
    if not callable(validate):
        return [("C7W_EXECUTION_AUTHORITY_GATE_INVALID","validate() missing")]
    try:
        rows=validate(root)
    except Exception as exc:
        return [("C7W_EXECUTION_AUTHORITY_GATE_INVALID",str(exc))]
    return list(rows) if isinstance(rows,list) else [("C7W_EXECUTION_AUTHORITY_GATE_INVALID","validate() result invalid")]


def validate(root:Path)->list[tuple[str,str]]:
    root=root.resolve(); errors:list[tuple[str,str]]=[]
    errors.extend(c7w_execution_errors(root))
    builder=read_required(root,"scripts/build_release_binaries.py",errors)
    verifier=read_required(root,"scripts/verify_release_build_toolchain.py",errors)
    packager=read_required(root,"scripts/build_release.py",errors)
    release_verifier=read_required(root,"scripts/verify_release.py",errors)
    exact_packager=read_required(root,"scripts/package_release_exact.py",errors)
    sealer=read_required(root,"scripts/seal_final_exact_release.py",errors)
    admission=read_required(root,"scripts/final_exact_release_admission.py",errors)
    stable_snapshot=read_required(root,"scripts/c9_stable_snapshot.py",errors)
    preflight=read_required(root,"scripts/c9_preflight.py",errors)
    makefile=read_required(root,"Makefile",errors)

    git_authority_sources=(
        ("scripts/build_release_binaries.py",builder),
        ("scripts/build_release.py",packager),
        ("scripts/package_release_exact.py",exact_packager),
        ("scripts/seal_final_exact_release.py",sealer),
        ("scripts/final_exact_release_admission.py",admission),
        ("scripts/c9_stable_snapshot.py",stable_snapshot),
    )
    for rel,text in git_authority_sources:
        missing_env=direct_git_calls_without_env(text)
        if missing_env:
            errors.append(("RELEASE_GIT_ENVIRONMENT_AUTHORITY_INVALID",f"{rel}:lines={','.join(str(x) for x in missing_env)}"))

    builder_markers=(
        'AUTHORITY="NATIVE_RELEASE_BINARY_BUILD_AUTHORITY_V1"',"release_build_environment","require_go_binary_identity",
        "require_cgo_toolchain_identity","require_release_build_host","normalized_machine",'env["GOPROXY"]="off"',
        'env["GOSUMDB"]="off"','env["GOWORK"]="off"','env["GOENV"]="off"','env["PYTHONDONTWRITEBYTECODE"]="1"',
        'env["PYTHONNOUSERSITE"]="1"','"PYTHONHOME","PYTHONPATH","PYTHONSTARTUP","PYTHONINSPECT"',
    )
    missing=[marker for marker in builder_markers if marker not in builder]
    if missing: errors.append(("RELEASE_BINARY_BUILDER_ENVIRONMENT_INVALID",",".join(missing)))

    builder_targets=literal_assignment(builder,"TARGETS"); packager_binaries=literal_assignment(packager,"BINARIES"); verifier_binaries=literal_assignment(release_verifier,"RELEASE_BINARIES")
    if builder_targets!=EXPECTED_BUILD_TARGETS: errors.append(("RELEASE_BINARY_TARGET_SET_INVALID",str(builder_targets)))
    if packager_binaries!=EXPECTED_RELEASE_BINARIES: errors.append(("RELEASE_PACKAGER_BINARY_SET_INVALID",str(packager_binaries)))
    if verifier_binaries!=EXPECTED_RELEASE_BINARIES: errors.append(("RELEASE_VERIFIER_BINARY_SET_INVALID",str(verifier_binaries)))

    verifier_markers=("verification_environment","release_binary_builder.release_build_environment()","current_go(env)","validate_active_cgo(lock,env)")
    missing=[marker for marker in verifier_markers if marker not in verifier]
    if missing: errors.append(("RELEASE_TOOLCHAIN_VERIFIER_ENVIRONMENT_INVALID",",".join(missing)))

    verifier_line='GO="$(GO)" $(PYTHON) scripts/verify_release_build_toolchain.py --require-admitted'
    builder_line='$(PYTHON) scripts/build_release_binaries.py --root . --go "$(GO)"'
    if verifier_line not in makefile or builder_line not in makefile:
        errors.append(("RELEASE_TOOLCHAIN_GO_SELECTOR_DRIFT","Makefile build-release must verify and build the same $(GO) selector"))

    packager_markers=('AUTHORITY="EXACT_RELEASE_PACKAGER_EXECUTION_V1"',"release_binary_builder.release_build_environment()","release_binary_builder.require_go_binary_identity","release_binary_builder.require_cgo_toolchain_identity",'env["GO"]=go_binary','[sys.executable,"scripts/build_release.py","."]')
    missing=[marker for marker in packager_markers if marker not in exact_packager]
    if missing: errors.append(("EXACT_RELEASE_PACKAGER_OWNER_INVALID",",".join(missing)))
    canonical_packager_line='GO="$(GO)" $(PYTHON) scripts/package_release_exact.py --root .'
    if canonical_packager_line not in makefile: errors.append(("EXACT_RELEASE_PACKAGER_OWNER_INVALID","Makefile release bypasses exact packager owner"))
    if '"scripts/package_release_exact.py"' not in sealer or '[sys.executable, "scripts/build_release.py", "."]' in sealer:
        errors.append(("FINAL_EXACT_RELEASE_PACKAGER_OWNER_INVALID","C9 must route packaging only through scripts/package_release_exact.py"))

    host_markers=("normalized_machine","FINAL_EXACT_RELEASE_LINUX_AMD64_HOST_REQUIRED",'"observedArchitecture"','"requiredArchitecture"')
    if any(marker not in sealer for marker in host_markers) or "require_release_build_host" not in builder:
        errors.append(("RELEASE_HOST_ARCHITECTURE_GUARD_INVALID","exact release must fail closed outside linux/amd64 in both builder and C9"))

    admission_markers=(
        'AUTHORITY="FINAL_EXACT_RELEASE_ADMISSION_V1"',
        "c7w_execution_provenance as execution_provenance",
        'execution_provenance.validate_rows(clients,certified_source_sha,"MCP_EXTERNAL_INTEROP",require_bound=True)',
        'execution_provenance.validate_rows(rows,progress.get("sourceCommitSHA"),"MCP_EXTERNAL_PROGRESS",require_bound=False)',
    )
    missing=[marker for marker in admission_markers if marker not in admission]
    if missing:
        errors.append(("FINAL_EXACT_RELEASE_C7W_PROVENANCE_INVALID",",".join(missing)))

    if not ordered_calls_on_same_path(sealer,"execute",("git_source","exact_source_admission","require_exact_release_host","require_exact_release_environment")):
        errors.append(("FINAL_EXACT_RELEASE_ADMISSION_ORDER_INVALID","fresh seal must admit exact source before host/environment work"))
    if not ordered_calls_on_same_path(sealer,"resume_existing_evidence",("exact_source_admission","require_exact_release_host","require_exact_release_environment")):
        errors.append(("FINAL_EXACT_RELEASE_ADMISSION_ORDER_INVALID","resume must re-admit sealed source before host/environment work"))
    if not ordered_calls_on_same_path(sealer,"execute",("admission.verify","safe_toolchain_archive","stage_toolchain_archive","extract_toolchain")):
        errors.append(("FINAL_EXACT_RELEASE_ADMISSION_ORDER_INVALID","detached exact-source admission must precede toolchain extraction"))
    if not c9_main_working_directory_bound(sealer):
        errors.append(("FINAL_EXACT_RELEASE_CLI_CONTEXT_INVALID","scripts/seal_final_exact_release.py"))
    if not c9_main_canonical_output_bound(sealer):
        errors.append(("FINAL_EXACT_RELEASE_CLI_OUTPUT_INVALID","scripts/seal_final_exact_release.py"))

    preflight_markers=(
        'AUTHORITY = "FINAL_EXACT_RELEASE_PREFLIGHT_HANDOFF_V1"',
        "sealer.exact_release_environment_preflight",
        "sealer.exact_source_admission",
        "validate_existing_evidence",
        '"INSPECT_C9_EXISTING_EVIDENCE"',
        '"FINAL_EXACT_RELEASE_EXISTING_EVIDENCE_FIELDS_INVALID"',
        '"MCP_EXTERNAL_INTEROP_PENDING"',
        '"RUN_C7W_PREFLIGHT"',
        '"RUN_C9_ON_EXACT_LINUX_HOST"',
        '"PROVIDE_C9_ENVIRONMENT_INPUTS"',
        '"RUN_C9_SEAL"',
        '"admissionReady"',
        '"requiredInputs"',
        '"physicalCertified"',
        "bind_execution_context",
        '"requiredWorkingDirectory"',
        '"<exact-source-checkout-root>"',
    )
    missing=[marker for marker in preflight_markers if marker not in preflight]
    if missing: errors.append(("FINAL_EXACT_RELEASE_PREFLIGHT_HANDOFF_INVALID",",".join(missing)))
    if 'c9-preflight:' not in makefile or 'scripts/c9_preflight.py --root .' not in makefile:
        errors.append(("FINAL_EXACT_RELEASE_PREFLIGHT_ENTRYPOINT_INVALID","Makefile c9-preflight must use scripts/c9_preflight.py"))
    return errors


def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--root",type=Path,default=Path(".")); args=parser.parse_args(); errors=validate(args.root)
    if errors:
        for code,detail in errors: print(f"{code} {detail}")
        return 1
    print(f"RELEASE_TOOL_AUTHORITY_GATE_PASS authority={AUTHORITY}")
    return 0

if __name__=="__main__": raise SystemExit(main())
