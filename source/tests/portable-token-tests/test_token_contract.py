"""Development token graphs only: no pickle bytes, VM.parse, torch or file payloads."""
import ast,hashlib,json,unittest
from pathlib import Path
from token_loader import load_tokens
# The portable runner supplies only path/SHA bindings after explicit --execute.
HERE=CONFIG=B=C=None
LIMITS={'max_pickle_opcodes':10000,'max_members':64,'max_file_bytes':4096,'max_scan_bytes':4096}
def machine(m):return m.LegacyMachine(dict(LIMITS))
def storage(m,v,kind='FloatStorage',location='cpu'):
    return v.persistent(('storage',v.global_token('torch',kind),'0',location,8,None))
def metadata(m,v,desc):
    if desc is None:return None
    if desc=='native-dict':return {'neg':True}
    if desc=='list':return m.LegacyList()
    if desc=='ordered-empty':return v.mapping(True)
    result=v.mapping(desc=='ordered-neg')
    values={'empty':{},'neg':{'neg':True},'false':{'neg':False},'int':{'neg':1},'string':{'neg':'True'},'bytes-key':{b'neg':True},'conj':{'conj':True},'extra':{'neg':True,'other':False},'ordered-neg':{'neg':True},'state':{'neg':True}}[desc]
    # Exact-key type traps deliberately represent an invalid abstract graph;
    # ordinary alias writes below always go through real VM SETITEMS.
    result.items.update(values) if desc=='bytes-key' else v.setitems(result,[item for pair in values.items() for item in pair])
    if desc=='state':result.state=v.mapping()
    return result
def reduce_token(m,v,meta=None,kind='FloatStorage',grad=False,hooks=None,location='cpu'):
    hooks=v.mapping(True) if hooks is None else hooks
    target=v.global_token('torch._utils','_rebuild_tensor_v2')
    args=(storage(m,v,kind,location),0,(1,),(1,),grad,hooks,meta)
    v.push(target);v.push(args);v.apply('REDUCE',None);return v.pop()
class Contract(unittest.TestCase):
    pass
CASES=[('none',None,'FloatStorage',False,True,True,(False,False)),('empty','empty','FloatStorage',False,True,True,(True,False)),('ordered_empty_preserved','ordered-empty','FloatStorage',False,True,True,(True,False)),('negative_float','neg','FloatStorage',False,False,True,(True,True)),('negative_half','neg','HalfStorage',False,False,True,(True,True)),('negative_bfloat','neg','BFloat16Storage',False,False,True,(True,True)),('negative_double','neg','DoubleStorage',False,False,True,(True,True)),('negative_float_grad','neg','FloatStorage',True,False,True,(True,True)),('false_not_clear','false','FloatStorage',False,False,False,None),('integer_one_not_bool','int','FloatStorage',False,False,False,None),('string_true','string','FloatStorage',False,False,False,None),('bytes_key','bytes-key','FloatStorage',False,False,False,None),('conjugate_not_supported','conj','FloatStorage',False,False,False,None),('extra_key','extra','FloatStorage',False,False,False,None),('ordered_nonempty','ordered-neg','FloatStorage',False,False,False,None),('stateful','state','FloatStorage',False,False,False,None),('native_dict_not_token','native-dict','FloatStorage',False,False,False,None),('list_not_map','list','FloatStorage',False,False,False,None),('negative_integer_storage','neg','IntStorage',False,False,False,None),('negative_bool_storage','neg','BoolStorage',False,False,False,None),('integer_grad_still_rejected','empty','IntStorage',True,False,False,None)]
def define_case(case):
    def test(self):
        label,desc,kind,grad,base_ok,new_ok,effect=case
        for module,expected in ((B,base_ok),(C,new_ok)):
            v=machine(module);meta=metadata(module,v,desc)
            if expected:
                tensor=reduce_token(module,v,meta,kind,grad);v.final_state(tensor)
                if module is C:self.assertIs(tensor.metadata, None if effect==(False,False) else effect[1])
            else:
                with self.assertRaises(module.LegacyTorchError):reduce_token(module,v,meta,kind,grad)
    return test
for case in CASES:setattr(Contract,'test_'+case[0],define_case(case))
def alias_test(name,operation):
    setattr(Contract,'test_'+name,operation)
def before_alias(self):
    v=machine(C);meta=metadata(C,v,'empty');v.push(meta);v.apply('BINPUT',0);v.pop();v.apply('BINGET',0);aliased=v.pop();v.setitems(aliased,['wrong',True])
    with self.assertRaises(C.LegacyTorchError):reduce_token(C,v,meta)
alias_test('metadata_preconsumption_memo_alias_revalidated',before_alias)
def after_alias(self):
    v=machine(C);meta=metadata(C,v,'neg');tensor=reduce_token(C,v,meta);v.setitems(meta,['unused_after_consumption',True]);v.final_state(tensor);self.assertIs(tensor.metadata,True)
alias_test('metadata_postconsumption_local_append_cannot_rewrite_effect',after_alias)
def empty_after(self):
    v=machine(C);meta=metadata(C,v,'empty');tensor=reduce_token(C,v,meta);v.setitems(meta,['neg',True]);v.final_state(tensor);self.assertIs(tensor.metadata,False)
alias_test('metadata_empty_then_append_not_retroactive_negative',empty_after)
def twice(self):
    v=machine(C);meta=metadata(C,v,'neg');first=reduce_token(C,v,meta);v.setitems(meta,['unsupported_second_use',True])
    with self.assertRaises(C.LegacyTorchError):reduce_token(C,v,meta)
    v.final_state(first);self.assertIs(first.metadata,True)
alias_test('metadata_second_consumer_revalidates_current_graph',twice)
def hook_alias(self):
    for module in (B,C):
        v=machine(module);hooks=v.mapping(True);tensor=reduce_token(module,v,None,hooks=hooks);v.push(hooks);v.apply('BINPUT',0);v.pop();v.apply('BINGET',0);v.setitems(v.pop(),['late_hook',True])
        with self.assertRaises(module.LegacyTorchError):v.final_state(tensor)
alias_test('hooks_retained_memo_alias_still_rejected',hook_alias)
def metadata_is_hooks(self):
    v=machine(C);shared=v.mapping(True);tensor=reduce_token(C,v,shared,hooks=shared);v.setitems(shared,['neg',True])
    with self.assertRaises(C.LegacyTorchError):v.final_state(tensor)
alias_test('metadata_snapshot_does_not_exempt_same_map_hooks',metadata_is_hooks)
def hooks_state(self):
    v=machine(C);hooks=v.mapping(True);tensor=reduce_token(C,v,None,hooks=hooks);hooks.state=v.mapping()
    with self.assertRaises(C.LegacyTorchError):v.final_state(tensor)
alias_test('hooks_late_state_still_rejected',hooks_state)
def malformed_effect(self):
    for effect in ((False,True),(1,True),[True,True],(True,),0,1,'neg'):
        v=machine(C);tensor=reduce_token(C,v,None);tensor.metadata=effect
        with self.assertRaises(C.LegacyTorchError):v.final_state(tensor)
alias_test('private_effect_slot_exact_none_or_bool_singletons',malformed_effect)
def noncpu(self):
    for module in (B,C):
        v=machine(module)
        with self.assertRaises(module.LegacyTorchError):reduce_token(module,v,None,location='cuda:0')
alias_test('non_cpu_remains_unsupported',noncpu)
def unknown(self):
    for module in (B,C):
        v=machine(module)
        with self.assertRaises(module.LegacyTorchError):v.global_token('os','system')
alias_test('unknown_dangerous_global_still_refused',unknown)
def no_guard_drift(self):
    a=ast.parse(Path(CONFIG['baselineSourcePath']).read_bytes());b=ast.parse((HERE/'scanner.py').read_bytes());allowed={('LegacyTensor','__init__'),('LegacyMachine','reduce'),('LegacyMachine','final_tokens')}
    for old,new in zip(a.body,b.body):
        if isinstance(old,ast.ClassDef) and old.name in {'LegacyTensor','LegacyMachine'}:
            for x,y in zip(old.body,new.body):
                if isinstance(x,ast.FunctionDef) and (old.name,x.name) not in allowed:self.assertEqual(ast.dump(x),ast.dump(y))
        elif not (isinstance(old,ast.ClassDef) and old.name=='LegacyTensor'):self.assertEqual(ast.dump(old),ast.dump(new))
alias_test('unrelated_ast_global_budget_limit_and_geometry_unchanged',no_guard_drift)
if __name__=='__main__':print(json.dumps({'mode':'DESCRIBE','testsRun':0,'sourceRead':False}))
