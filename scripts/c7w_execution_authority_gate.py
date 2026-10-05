#!/usr/bin/env python3
"""Fail closed if the local C7W execution/reconciliation owner graph drifts."""
from __future__ import annotations

import argparse
import ast
from pathlib import Path

AUTHORITY="C7W_EXECUTION_AUTHORITY_GATE_V1"
REQUIRED_FILES=(
    "scripts/c7w_preflight.py",
    "scripts/prepare_c7w_oauth_bindings.py",
    "scripts/reconcile_c7w_trusted_clients.py",
    "scripts/c7w_execution_bindings.py",
    "scripts/c7w_credential_profiles.py",
    "scripts/c7w_execution_provenance.py",
    "scripts/run_mcp_external_interop.py",
    "scripts/prepare_mcp_external_interop_campaign.py",
    "scripts/seal_mcp_external_interop.py",
    "scripts/prepare_mcp_external_client_execution.py",
    "scripts/finalize_mcp_external_client_receipt.py",
    "scripts/admit_mcp_external_receipt.py",
)
PLACEHOLDERS=("<foreign-project-id>","<same-project-operation-id>","<request-created-by-same-subject>")


def read(root:Path,rel:str,errors:list[tuple[str,str]])->str:
    path=root/rel
    if path.is_symlink() or not path.is_file():
        errors.append(("C7W_EXECUTION_OWNER_MISSING",rel)); return ""
    try: return path.read_text(encoding="utf-8",errors="strict")
    except (OSError,UnicodeDecodeError) as exc:
        errors.append(("C7W_EXECUTION_OWNER_INVALID",f"{rel}:{exc}")); return ""


def direct_git_calls_without_env(source:str)->list[int]:
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
            and isinstance(command.elts[0],ast.Constant)
            and command.elts[0].value=="git"
        ):
            continue
        if not any(keyword.arg=="env" for keyword in node.keywords):
            missing.append(getattr(node,"lineno",0))
    return missing


def function_scope_nodes(function:ast.FunctionDef|ast.AsyncFunctionDef):
    """Walk definitely reachable syntax in one owner without accepting nested/dead wiring."""
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
        return [node.target],None
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
        def whole_subject_aliases(pattern):
            if isinstance(pattern,ast.MatchAs) and pattern.name:
                return [ast.Name(id=pattern.name,ctx=ast.Store())]
            if isinstance(pattern,ast.MatchOr):
                return [target for child in pattern.patterns for target in whole_subject_aliases(child)]
            return []
        for case in node.cases:
            targets.extend(whole_subject_aliases(case.pattern))
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
        if not direct_authority_exposure(value,owner):
            continue
        for root_target in targets:
            for target in assignment_target_nodes(root_target):
                if isinstance(target,(ast.Tuple,ast.List)):
                    continue
                if isinstance(target,ast.Name) and target.id==owner:
                    continue
                return True
    return False


def mutable_authority_mapping_alias_value(value,owner:str)->bool:
    if owner!="args":
        return False
    if (
        isinstance(value,ast.Attribute)
        and value.attr=="__dict__"
        and isinstance(value.value,ast.Name)
        and value.value.id==owner
    ):
        return True
    return (
        isinstance(value,ast.Call)
        and isinstance(value.func,ast.Name)
        and value.func.id=="vars"
        and len(value.args)==1
        and isinstance(value.args[0],ast.Name)
        and value.args[0].id==owner
    )


def direct_authority_exposure(value,owner:str)->bool:
    if isinstance(value,ast.Name) and value.id==owner:
        return True
    if mutable_authority_mapping_alias_value(value,owner):
        return True
    if isinstance(value,(ast.Tuple,ast.List,ast.Set)):
        return any(direct_authority_exposure(item,owner) for item in value.elts)
    if isinstance(value,ast.Dict):
        return any(direct_authority_exposure(item,owner) for item in [*value.keys,*value.values] if item is not None)
    if isinstance(value,ast.Starred):
        return direct_authority_exposure(value.value,owner)
    if isinstance(value,ast.IfExp):
        return direct_authority_exposure(value.body,owner) or direct_authority_exposure(value.orelse,owner)
    if isinstance(value,ast.BoolOp):
        return any(direct_authority_exposure(item,owner) for item in value.values)
    if isinstance(value,(ast.ListComp,ast.SetComp,ast.GeneratorExp)):
        return direct_authority_exposure(value.elt,owner)
    if isinstance(value,ast.DictComp):
        return direct_authority_exposure(value.key,owner) or direct_authority_exposure(value.value,owner)
    if isinstance(value,ast.Subscript):
        try:
            index=ast.literal_eval(value.slice)
        except (ValueError,TypeError,SyntaxError):
            return False
        container=value.value
        if isinstance(container,(ast.Tuple,ast.List)) and isinstance(index,int):
            try:
                return direct_authority_exposure(container.elts[index],owner)
            except IndexError:
                return False
        if isinstance(container,ast.Dict):
            for key,item in reversed(list(zip(container.keys,container.values))):
                try:
                    matches=ast.literal_eval(key)==index
                except (ValueError,TypeError,SyntaxError):
                    continue
                if matches:
                    return direct_authority_exposure(item,owner)
    return False


def default_authority_capture_present(function:ast.FunctionDef|ast.AsyncFunctionDef,owner:str)->bool:
    for node in function_scope_nodes(function):
        if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.Lambda)) or node is function:
            continue
        defaults=(*node.args.defaults,*node.args.kw_defaults)
        if any(default is not None and direct_authority_exposure(default,owner) for default in defaults):
            return True
    return False


def nested_scope_closure_capture(node,owner:str)->bool:
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


def closure_authority_capture_present(function:ast.FunctionDef|ast.AsyncFunctionDef,owner:str)->bool:
    for node in function_scope_nodes(function):
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.Lambda)) and node is not function:
            if nested_scope_closure_capture(node,owner):
                return True
    return False


def runner_root_value_valid(value)->bool:
    return (
        isinstance(value,ast.Call)
        and isinstance(value.func,ast.Attribute)
        and value.func.attr=="resolve"
        and not value.args
        and isinstance(value.func.value,ast.Call)
        and isinstance(value.func.value.func,ast.Attribute)
        and value.func.value.func.attr=="cwd"
        and not value.func.value.args
        and isinstance(value.func.value.func.value,ast.Name)
        and value.func.value.func.value.id=="Path"
    )


def canonical_runner_root_bound(function:ast.FunctionDef|ast.AsyncFunctionDef)->bool:
    binding_line=None
    for node in function.body:
        targets,value=assignment_targets_and_value(node)
        for target in (item for root_target in targets for item in assignment_target_nodes(root_target)):
            if isinstance(target,ast.Name) and target.id=="root":
                direct=len(targets)==1 and targets[0] is target and not isinstance(node,ast.AugAssign)
                if binding_line is not None or not direct or not runner_root_value_valid(value):
                    return False
                binding_line=getattr(node,"lineno",0)
    if binding_line is None or closure_authority_capture_present(function,"root"):
        return False
    for node in function_scope_nodes(function):
        if getattr(node,"lineno",0)<=binding_line:
            continue
        targets,_=assignment_targets_and_value(node)
        if any(isinstance(target,ast.Name) and target.id=="root" for root_target in targets for target in assignment_target_nodes(root_target)):
            return False
        if isinstance(node,ast.Delete) and any(isinstance(target,ast.Name) and target.id=="root" for target in node.targets):
            return False
    return True


def call_name(node)->str:
    if not isinstance(node,ast.Call):
        return ""
    if isinstance(node.func,ast.Name):
        return node.func.id
    if isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name):
        return f"{node.func.value.id}.{node.func.attr}"
    return ""


def unknown_authority_helper_call(node,owner:str,allowed:tuple[str,...]=())->bool:
    if not isinstance(node,ast.Call) or call_name(node) in set(allowed):
        return False
    return any(direct_authority_exposure(arg,owner) for arg in node.args) or any(direct_authority_exposure(keyword.value,owner) for keyword in node.keywords)


def canonical_guard_value_valid(value,attr:str)->bool:
    expected_rel="CANONICAL_PROGRESS_REL" if attr=="progress_out" else "CANONICAL_EVIDENCE_REL"
    expected_label="PROGRESS" if attr=="progress_out" else "EVIDENCE"
    return (
        isinstance(value,ast.Call)
        and isinstance(value.func,ast.Name)
        and value.func.id=="require_canonical_artifact_path"
        and len(value.args)>=4
        and isinstance(value.args[0],ast.Name)
        and value.args[0].id=="root"
        and isinstance(value.args[1],ast.Attribute)
        and isinstance(value.args[1].value,ast.Name)
        and value.args[1].value.id=="args"
        and isinstance(value.args[2],ast.Name)
        and value.args[2].id==expected_rel
        and isinstance(value.args[3],ast.Constant)
        and value.args[3].value==expected_label
    )


def args_attribute_call_mutation(node)->str|None:
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


def working_directory_value_valid(value)->bool:
    return isinstance(value,ast.Call) and isinstance(value.func,ast.Name) and value.func.id=="str" and len(value.args)==1 and isinstance(value.args[0],ast.Name) and value.args[0].id=="root"


def result_mutation_call(node)->bool:
    return isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=="result" and node.func.attr in ("update","clear","pop","popitem","__setitem__","__delitem__")


def external_client_action_contract_errors(source:str)->list[str]:
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return ["RUNNER_SYNTAX_INVALID"]
    functions={node.name:node for node in tree.body if isinstance(node,ast.FunctionDef)}
    helper=functions.get("external_client_action")
    if helper is None:
        return ["EXTERNAL_ACTION_OWNER_MISSING"]
    returns=[node for node in function_scope_nodes(helper) if isinstance(node,ast.Return)]
    def valid_return(node:ast.Return)->bool:
        if not isinstance(node.value,ast.Dict):
            return False
        mapping={}
        for key,value in zip(node.value.keys,node.value.values):
            if isinstance(key,ast.Constant) and isinstance(key.value,str):
                mapping[key.value]=value
        action=mapping.get("nextActionCode")
        command=mapping.get("nextCommand")
        return isinstance(action,ast.Constant) and action.value=="RUN_EXTERNAL_CLIENT" and isinstance(command,ast.List) and not command.elts and "nextClientHandoff" in mapping and "postExternalExecutionCommand" in mapping
    def static_string_value(node):
        if isinstance(node,ast.Constant) and isinstance(node.value,str):
            return node.value
        if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Add):
            left=static_string_value(node.left); right=static_string_value(node.right)
            if left is not None and right is not None:
                return left+right
        return None
    errors=[]
    if not returns or not all(valid_return(node) for node in returns):
        errors.append("EXTERNAL_ACTION_SHAPE_INVALID")
    for owner in ("prepare","admit","status"):
        fn=functions.get(owner)
        if fn is None:
            errors.append(f"{owner.upper()}_OWNER_MISSING")
            continue
        wired=any(isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="external_client_action" for node in function_scope_nodes(fn))
        if not wired:
            errors.append(f"{owner.upper()}_EXTERNAL_ACTION_WIRING_INVALID")
        direct_emission=any(static_string_value(node)=="RUN_EXTERNAL_CLIENT" for node in function_scope_nodes(fn))
        if direct_emission:
            errors.append(f"{owner.upper()}_EXTERNAL_ACTION_DIRECT_EMISSION_INVALID")
    return errors


def canonical_output_contract_errors(source:str)->list[str]:
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return ["RUNNER_SYNTAX_INVALID"]
    expected={"CANONICAL_PROGRESS_REL":"lab/mcp-external-client-interop-progress.json","CANONICAL_EVIDENCE_REL":"lab/mcp-external-client-interoperability-evidence.json"}
    constants={}
    functions={node.name:node for node in tree.body if isinstance(node,ast.FunctionDef)}
    for node in tree.body:
        if not isinstance(node,ast.Assign) or len(node.targets)!=1 or not isinstance(node.targets[0],ast.Name):
            continue
        name=node.targets[0].id
        if name not in expected or not isinstance(node.value,ast.Call):
            continue
        if not isinstance(node.value.func,ast.Name) or node.value.func.id!="Path" or len(node.value.args)!=1:
            continue
        arg=node.value.args[0]
        if isinstance(arg,ast.Constant) and isinstance(arg.value,str):
            constants[name]=arg.value
    errors=[]
    for name,value in expected.items():
        if constants.get(name)!=value:
            errors.append(name+"_INVALID")
    if "require_canonical_artifact_path" not in functions:
        errors.append("CANONICAL_OUTPUT_GUARD_MISSING")
    main=functions.get("main")
    if main is None:
        errors.append("MAIN_OWNER_MISSING")
        return errors
    guarded={"progress_out":False,"evidence_out":False}
    guard_lines={"progress_out":None,"evidence_out":None}
    for node in main.body:
        if isinstance(node,(ast.Return,ast.Raise)):
            break
        targets,value=assignment_targets_and_value(node)
        if not targets:
            continue
        for target in (item for root_target in targets for item in assignment_target_nodes(root_target)):
            if not (isinstance(target,ast.Attribute) and isinstance(target.value,ast.Name) and target.value.id=="args" and target.attr in guarded):
                continue
            attr=target.attr
            direct_target=len(targets)==1 and targets[0] is target and not isinstance(node,ast.AugAssign)
            guarded[attr]=direct_target and canonical_guard_value_valid(value,attr)
            guard_lines[attr]=getattr(node,"lineno",0) if guarded[attr] else None
    for attr in guarded:
        line=guard_lines[attr]
        if not guarded[attr] or line is None:
            continue
        for node in function_scope_nodes(main):
            if getattr(node,"lineno",0)<=line:
                continue
            targets,value=assignment_targets_and_value(node)
            for target in (item for root_target in targets for item in assignment_target_nodes(root_target)):
                if not (isinstance(target,ast.Attribute) and isinstance(target.value,ast.Name) and target.value.id=="args" and target.attr==attr):
                    continue
                direct_target=len(targets)==1 and targets[0] is target and not isinstance(node,ast.AugAssign)
                if not (direct_target and canonical_guard_value_valid(value,attr)):
                    guarded[attr]=False
            if args_attribute_call_mutation(node)==attr:
                guarded[attr]=False
    if not canonical_runner_root_bound(main) or direct_authority_alias_present(main,"args") or default_authority_capture_present(main,"args") or closure_authority_capture_present(main,"args"):
        guarded={"progress_out":False,"evidence_out":False}
    for node in function_scope_nodes(main):
        targets,value=assignment_targets_and_value(node)
        flat_targets=[item for root_target in targets for item in assignment_target_nodes(root_target)]
        if direct_authority_exposure(value,"args") and any(isinstance(target,ast.Name) and target.id!="args" for target in flat_targets):
            guarded={"progress_out":False,"evidence_out":False}
        if unknown_authority_helper_call(node,"args",("prepare","admit","seal","status")):
            guarded={"progress_out":False,"evidence_out":False}
    if not guarded["progress_out"]:
        errors.append("PROGRESS_OUTPUT_WIRING_INVALID")
    if not guarded["evidence_out"]:
        errors.append("EVIDENCE_OUTPUT_WIRING_INVALID")
    return errors


def runner_working_directory_contract_errors(source:str)->list[str]:
    try:
        tree=ast.parse(source)
    except (SyntaxError,ValueError):
        return ["RUNNER_SYNTAX_INVALID"]
    main=next((node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="main"),None)
    if main is None:
        return ["MAIN_OWNER_MISSING"]
    working_valid=False
    working_line=None
    for node in main.body:
        if isinstance(node,(ast.Return,ast.Raise)):
            break
        targets,value=assignment_targets_and_value(node)
        if not targets:
            continue
        flat_targets=[item for root_target in targets for item in assignment_target_nodes(root_target)]
        if any(isinstance(target,ast.Name) and target.id=="result" for target in flat_targets):
            working_valid=False
            working_line=None
        for target in flat_targets:
            if not (isinstance(target,ast.Subscript) and isinstance(target.value,ast.Name) and target.value.id=="result" and isinstance(target.slice,ast.Constant) and target.slice.value=="workingDirectory"):
                continue
            direct_target=len(targets)==1 and targets[0] is target and not isinstance(node,ast.AugAssign)
            working_valid=direct_target and working_directory_value_valid(value)
            working_line=getattr(node,"lineno",0) if working_valid else None
    if working_valid and working_line is not None:
        for node in function_scope_nodes(main):
            if getattr(node,"lineno",0)<=working_line:
                continue
            targets,value=assignment_targets_and_value(node)
            flat_targets=[item for root_target in targets for item in assignment_target_nodes(root_target)]
            if any(isinstance(target,ast.Name) and target.id=="result" for target in flat_targets):
                working_valid=False
            for target in flat_targets:
                if not (isinstance(target,ast.Subscript) and isinstance(target.value,ast.Name) and target.value.id=="result" and isinstance(target.slice,ast.Constant) and target.slice.value=="workingDirectory"):
                    continue
                direct_target=len(targets)==1 and targets[0] is target and not isinstance(node,ast.AugAssign)
                if not (direct_target and working_directory_value_valid(value)):
                    working_valid=False
            if result_mutation_call(node):
                working_valid=False
    if not canonical_runner_root_bound(main) or direct_authority_alias_present(main,"result") or default_authority_capture_present(main,"result") or closure_authority_capture_present(main,"result"):
        working_valid=False
    for node in function_scope_nodes(main):
        targets,value=assignment_targets_and_value(node)
        flat_targets=[item for root_target in targets for item in assignment_target_nodes(root_target)]
        if direct_authority_exposure(value,"result") and any(isinstance(target,ast.Name) and target.id!="result" for target in flat_targets):
            working_valid=False
        if unknown_authority_helper_call(node,"result",("json.dumps",)):
            working_valid=False
    return [] if working_valid else ["RUNNER_WORKING_DIRECTORY_WIRING_INVALID"]


def validate(root:Path)->list[tuple[str,str]]:
    root=root.resolve(); errors:list[tuple[str,str]]=[]
    source={rel:read(root,rel,errors) for rel in REQUIRED_FILES}
    preflight=source["scripts/c7w_preflight.py"]
    materializer=source["scripts/prepare_c7w_oauth_bindings.py"]
    reconciler=source["scripts/reconcile_c7w_trusted_clients.py"]
    execution=source["scripts/c7w_execution_bindings.py"]
    profiles=source["scripts/c7w_credential_profiles.py"]
    provenance=source["scripts/c7w_execution_provenance.py"]
    runner=source["scripts/run_mcp_external_interop.py"]
    campaign=source["scripts/prepare_mcp_external_interop_campaign.py"]
    seal=source["scripts/seal_mcp_external_interop.py"]
    packet=source["scripts/prepare_mcp_external_client_execution.py"]
    finalizer=source["scripts/finalize_mcp_external_client_receipt.py"]
    admit=source["scripts/admit_mcp_external_receipt.py"]

    for rel,text in (("scripts/c7w_preflight.py",preflight),("scripts/c7w_execution_bindings.py",execution),("scripts/run_mcp_external_interop.py",runner),("scripts/prepare_mcp_external_interop_campaign.py",campaign),("scripts/seal_mcp_external_interop.py",seal)):
        missing_env=direct_git_calls_without_env(text)
        if missing_env:
            errors.append(("C7W_GIT_ENVIRONMENT_AUTHORITY_INVALID",f"{rel}:lines={','.join(str(x) for x in missing_env)}"))

    reconciliation_markers=('AUTHORITY="MCP_EXTERNAL_TRUSTED_CLIENT_RECONCILIATION_V1"',"def reconcile_plan","def reconcile(","before=fetch_rows","create_row(","after=fetch_rows",'"status=409"',"def preflight_command")
    missing=[marker for marker in reconciliation_markers if marker not in reconciler]
    if missing: errors.append(("C7W_RECONCILIATION_OWNER_INVALID",",".join(missing)))
    if "def trusted_client_reconcile_command" not in preflight or "scripts/reconcile_c7w_trusted_clients.py" not in preflight or '"RECONCILE_C7W_TRUSTED_CLIENTS"' not in preflight: errors.append(("C7W_RECONCILIATION_WIRING_INVALID","scripts/c7w_preflight.py"))
    if ".state/private/c7w-oauth-client-bindings.json" not in materializer or "followup_preflight_command" not in materializer: errors.append(("C7W_OAUTH_MATERIALIZER_OWNER_INVALID","scripts/prepare_c7w_oauth_bindings.py"))

    execution_markers=('AUTHORITY="MCP_EXTERNAL_EXECUTION_BINDINGS_V1"','DEFAULT_OUTPUT=Path(".state/private/c7w-execution-bindings.json")',"def validate_document","def canonical_output_path","def materialize","credentialProfileContractSha256")
    missing=[marker for marker in execution_markers if marker not in execution]
    if missing: errors.append(("C7W_EXECUTION_BINDINGS_OWNER_INVALID",",".join(missing)))
    if 'AUTHORITY="MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1"' not in profiles or "def contract" not in profiles or "def contract_digest" not in profiles: errors.append(("C7W_CREDENTIAL_PROFILE_OWNER_INVALID","scripts/c7w_credential_profiles.py"))
    provenance_markers=('EXECUTION_BINDING_AUTHORITY="MCP_EXTERNAL_EXECUTION_BINDINGS_V1"','CREDENTIAL_PROFILE_CONTRACT_AUTHORITY="MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1"',"def credential_contract_digest","credential_profiles.contract_digest()","credential_digest!=credential_contract_digest()","EXECUTION_BINDING_CREDENTIAL_CONTRACT_INVALID","def projection","def validate_rows","def validate_receipt_execution_binding","EXECUTION_BINDING_MIXED","EXECUTION_BINDING_REQUIRED")
    missing=[marker for marker in provenance_markers if marker not in provenance]
    if missing: errors.append(("C7W_EXECUTION_PROVENANCE_OWNER_INVALID",",".join(missing)))
    if "PREPARE_C7W_EXECUTION_BINDINGS" not in preflight or "scripts/c7w_execution_bindings.py" not in preflight or "executionBindingsSha256" not in preflight or "DEFAULT_EXECUTION_BINDING_REL" not in preflight or "MCP_EXTERNAL_EXECUTION_BINDINGS_PATH_INVALID" not in preflight: errors.append(("C7W_EXECUTION_BINDINGS_WIRING_INVALID","scripts/c7w_preflight.py"))
    if 'AUTHORITY="MCP_EXTERNAL_LOCAL_EXECUTION_RUNNER_V1"' not in runner or "def runner_command" not in runner: errors.append(("C7W_LOCAL_RUNNER_OWNER_INVALID","scripts/run_mcp_external_interop.py"))
    external_action_errors=external_client_action_contract_errors(runner)
    if external_action_errors: errors.append(("C7W_LOCAL_RUNNER_EXTERNAL_ACTION_INVALID",",".join(external_action_errors)))
    canonical_output_errors=canonical_output_contract_errors(runner)
    if canonical_output_errors: errors.append(("C7W_LOCAL_RUNNER_CANONICAL_OUTPUT_INVALID",",".join(canonical_output_errors)))
    working_directory_errors=runner_working_directory_contract_errors(runner)
    if working_directory_errors: errors.append(("C7W_LOCAL_RUNNER_WORKING_DIRECTORY_INVALID",",".join(working_directory_errors)))
    campaign_markers=('AUTHORITY=core.CAMPAIGN_AUTHORITY',"def source_commit_sha","def execution_binding_snapshot","def normalize_execution_binding_snapshot","canonical_execution_binding_required(matrix_path)","executionBindingsSha256","MCP_EXTERNAL_CAMPAIGN_EXECUTION_BINDING_DRIFT")
    missing=[marker for marker in campaign_markers if marker not in campaign]
    if missing: errors.append(("C7W_CAMPAIGN_OWNER_INVALID",",".join(missing)))
    seal_markers=('AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_EVIDENCE_V1"',"def validate_evidence_only_source_lineage","def validate_receipt_execution_binding","validate_receipt_execution_binding(row,campaign,client)","**execution_binding",'execution_provenance.validate_rows(rows,source_commit_sha,"MCP_EXTERNAL_EVIDENCE",require_bound=True)')
    missing=[marker for marker in seal_markers if marker not in seal]
    if missing: errors.append(("C7W_SEAL_OWNER_INVALID",",".join(missing)))
    if 'AUTHORITY="MCP_EXTERNAL_CLIENT_EXECUTION_PACKET_V1"' not in packet or "executionBindingsSha256" not in packet or "credentialProfileContract" not in packet or "_binding_snapshot" not in packet: errors.append(("C7W_EXECUTION_PACKET_OWNER_INVALID","scripts/prepare_mcp_external_client_execution.py"))
    finalizer_markers=("_packet_execution_bindings","credentialProfileContractSha256","executionBindingsSha256",'"executionBindings":resources')
    missing=[marker for marker in finalizer_markers if marker not in finalizer]
    if missing: errors.append(("C7W_RECEIPT_FINALIZER_OWNER_INVALID",",".join(missing)))
    admit_markers=("execution_provenance.validate_rows","core.validate_receipt_execution_binding","def validate_existing_campaign_rows")
    missing=[marker for marker in admit_markers if marker not in admit]
    if missing: errors.append(("C7W_PROGRESS_PROVENANCE_OWNER_INVALID",",".join(missing)))
    for rel,text in (("scripts/prepare_mcp_external_client_execution.py",packet),("scripts/finalize_mcp_external_client_receipt.py",finalizer)):
        for placeholder in PLACEHOLDERS:
            if placeholder in text: errors.append(("C7W_EXECUTION_PLACEHOLDER_FORBIDDEN",f"{rel}:{placeholder}"))
    return errors


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--root",type=Path,default=Path(".")); args=p.parse_args(); errors=validate(args.root)
    if errors:
        for code,detail in errors: print(f"{code} {detail}")
        return 1
    print(f"C7W_EXECUTION_AUTHORITY_GATE_PASS authority={AUTHORITY}")
    return 0

if __name__=="__main__": raise SystemExit(main())