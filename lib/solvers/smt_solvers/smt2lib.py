"""Functions to parse SMT2 model"""

from typing import Any, Dict, List, Tuple, Union


class DefaultDict(dict):
    def __init__(self, dictionary: Dict[Any, Any], default_value: Any) -> None:
        self.dictionary = dictionary
        self.default_value = default_value

    def __getitem__(self, key: Any) -> Any:
        return self.dictionary.get(key, self.default_value)

    def get(self, key: Any, default_value: Any) -> Any:
        return self.dictionary.get(key, default_value)

    def __setitem__(self, key: Any, val: Any) -> Any:
        self.dictionary.__setitem__(key, val)


############# parsing #############


def _parse_ite(entry: str) -> Tuple[str, str, Union[int, DefaultDict]]:
    name, entry = entry.split("\n", 1)
    name = name.rstrip(" (")
    args_type, entry = entry.split("\n", 1)
    _, type_ = args_type.split(") (", 1)
    # args = args.strip()
    type_ = "(" + type_.strip()
    entry_list = [e for e in entry.split("\n") if e != ')'] # remove trailing closing bracket opened by '(model'
    default_val = int(entry_list[-1].rstrip(")").strip().replace('#', '0'), 2)
    entry_list = [e.strip() for e in entry_list[:-1]]
    ite_dict = {}
    for e in entry_list:
        assert "ite" in e, f"failed to find ite in {e}"
        vals = e.split("#")
        key_val = int("0" + vals[1].rstrip(") "), 2)
        val_val = int("0" + vals[2], 2)
        ite_dict[key_val] = val_val
    return name, type_, DefaultDict(ite_dict, default_val)


def _parse_no_args(entry: str) -> Tuple[str, str, int]:
    parts = entry.strip().split(" ")
    assert parts[1].strip() == "()", f"() != {parts[1]} (no arguments expected but some found)"
    return (parts[0].strip(), ' '.join(parts[2:5]), int(parts[-1].replace('#','0').rstrip(')'), 2))


def _parse_line(entry: str) -> Tuple[str, str, Union[int, DefaultDict]]:
    if "ite" in entry:
        return _parse_ite(entry)
    else:
        return _parse_no_args(entry)


def to_int(num: str) -> int:
    assert isinstance(num, str), f"Number {num} not a str"
    if num.startswith("#b"):
        return int(num[2:], 2)
    if num.startswith("#x"):
        return int(num[2:], 16)
    return int(num)


def parse_stack_assignments(model_text: str, size: int, little_endian: bool = True) -> Dict[int, int]:
    """Parse stack assignments - works only if StackMode.Explicit is set"""
    addr_to_bytes = {}
    for l in model_text.splitlines():
        if "define-fun" and "stack" in l:
            addr = int(l.split("stack", 1)[1].split(" ", 1)[0])
            val = to_int(l.split("(_ BitVec 8) ")[1].rstrip(")"))
            addr_to_bytes.update({addr:val})
    addr_to_size = {}
    assert size % 8 == 0, f"Expected size to be a multiple of 8 - but found {size} bits"
    bsize = size // 8
    addrs = sorted(addr_to_bytes.keys())
    assert len(addrs) % bsize == 0, f"Expected the number of stack assignments to be divisible by {bsize} bytes"
    for i in range(0, len(addrs), bsize):
        val = 0
        for j in range(bsize):
            if little_endian:
                val += addr_to_bytes[addrs[i+j]] << (8 * j)
            else:
                val += addr_to_bytes[addrs[i+j]] << (8 * (bsize - 1 - j))
        addr_to_size.update({addrs[i] : val})
    return addr_to_size

##############################################################

def deduplicate_model_str(model_text: str) -> str:
    parts = model_text.split("\n)\n(\n")
    if len(parts) == 1:
        return parts[0].lstrip("(\n").rstrip().rstrip("\n)")
    if len(parts) == 2:
        parts[0] = parts[0].strip().lstrip("(").strip() # remove initial opening bracket
        parts[1] = parts[1].strip().rstrip(")").strip() # remove final closing bracket
        assert len(parts[0]) == len(parts[1]), f"Not a duplicate model: len(m0)={len(parts[0])}, len(m1)={len(parts[1])}"
        assert parts[0] == parts[1], "Duplicate model seems to be not equal!"
        return parts[0]
    raise RuntimeError(f"Model is neither once or twice contained: found {len(parts)} models")

def parse_expr(tokens: List[str]) -> Tuple[int, List[str]]:
    if tokens[0] != "(":
        return 1, [tokens[0]]
    lvl = 0
    expr = []
    for (i, t) in enumerate(tokens):
        expr += [t]
        if t == "(":
            lvl += 1
        if t == ")":
            lvl -= 1
        if lvl == 0:
            return i + 1, expr
    raise RuntimeError(f"Unterminated clause - {lvl} brackets not closed")

def parse_equal_expr(tokens: List[str]) -> Tuple[str, int]:
    assert tokens[0] == "(" and tokens[1] == "=", f"Expected ['(', '=', ...] but found ['{tokens[0]}', '{tokens[1]}', ...]"
    return tokens[2].strip(), to_int(tokens[3].strip())

def parse_ite_val(d: Dict[int, int], tokens: List[str], name: str) -> DefaultDict: # Tuple[Optional[int], Dict[int, int]]:
    assert tokens[0] == "(" and tokens[1] == "ite", f"Expected ['(', 'ite', ...] but found ['{tokens[0]}', '{tokens[1]}', ...]"
    tokens = tokens[2:]
    # print(f"INIT: {tokens[:20]}")
    # if
    offset, cond = parse_expr(tokens)
    tokens = tokens[offset:]
    # print(f"cond={cond}")
    cond_name, if_value = parse_equal_expr(cond)
    assert name in cond_name, f"parse_ite_val: {name} not in {cond_name}"
    # print(f"if_value={if_value:#x}")
    # then
    offset, val_str = parse_expr(tokens)
    tokens = tokens[offset:]
    # TODO: probably we want to handle this like the else case and just call parse_ite_val if it isn't a simple value
    assert len(val_str) == 1, f"expr should be value but is: {val_str}"
    then_value = to_int(val_str[0])
    # print(f"then_value={then_value:#x}")
    d[if_value] = then_value
    # else
    offset, else_tokens = parse_expr(tokens)
    tokens = tokens[offset:]
    # print(f"else_value={else_tokens}")
    if len(else_tokens) > 2 and else_tokens[1] == "ite":
        return parse_ite_val(d, else_tokens, name)
    elif len(else_tokens) != 1:
        raise RuntimeError(f"Expected a single entry - the default value but found: {else_tokens}")
    return DefaultDict(d, to_int(else_tokens[0]))

def parse_ite_val_fast(d: Dict[int, int], tokens: List[str]) -> DefaultDict:
    # assume nested ITEs have fixed pattern IF(cond) THEN(simple value) ELSE: another ITE (or finally default value)
    # not flexibe but 180x times faster
    num_ites = tokens.count("ite")
    ites = []
    cur_ite: List[str] = []
    for t in tokens:
        if t == "ite":
            ites.append(cur_ite)
            cur_ite = []
        else:
            cur_ite.append(t)
    ites = ites[1:]
    for ite in ites:
        _, if_value = parse_equal_expr(ite[:-3])
        then_value = to_int(ite[-2])
        d[if_value] = then_value
    default_value = to_int(tokens[-num_ites-1])
    return DefaultDict(d, default_value)

def parse_ite_definition(tokens: List[str], name: str) -> DefaultDict:
    tokens = tokens[3:-1] # skip initial bracket, last bracket and name
    offset, arg = parse_expr(tokens)
    tokens = tokens[offset:]
    # print(f"ARG={arg}")
    offset, ret_type = parse_expr(tokens)
    tokens = tokens[offset:]
    # print(f"type={ret_type}")
    offset, val_tokens = parse_expr(tokens)
    try:
        def_dict = parse_ite_val_fast({}, val_tokens)
    except: # fallback to slow parsing
        def_dict = parse_ite_val({}, val_tokens, name)
    return def_dict

def parse_definitions(model_text: str) -> List[str]:
    lines = model_text.splitlines()
    elements = []
    cur_element = ""
    mismatch = 0
    multiline = False
    for line in lines:
        bo = line.count("(")
        bc = line.count(")")
        if not multiline:
            if bo == bc: # single line entry
                elements.append(line.strip())
            elif bo > bc: # start multiline entry
                multiline = True
                mismatch = bo - bc
                cur_element = line
            else: # not a multiline but closing more brackets than we opened - weird
                raise RuntimeError(f"Unexpected case {line.count('(')}x '(' vs {line.count(')')}x ')': {line}")
        else: # multiline
            cur_element += " " + line
            mismatch += (bo - bc)
            if mismatch < 0:
                raise RuntimeError("Closed too many brackets")
            if mismatch == 0:
                elements.append(cur_element.strip())
                multiline = False
                cur_element = ""
    assert multiline == False, "Multiline not completed"
    assert mismatch == 0, f"mismatch != 0, is: {mismatch}"
    assert cur_element == "", f"cur_element not finished: {cur_element[:100]}..."
    return elements

def tokenize(string: str) -> List[str]:
    return [e.strip() for e in string.replace("(", " ( ").replace(")", " ) ").replace("  ", " ").split() if e.strip()]

def parse_smt2lib_model(model_text: str) -> Dict[str, Union[int, DefaultDict]]:
    """Another hacky parsing of smt2lib produced model, but at least capable of multilines!"""
    if not model_text.startswith("(\n"):
        raise Exception("Not an smt2lib model (expected to start with '(\\n')")

    model_text = deduplicate_model_str(model_text)

    # from now on, consider only first model - initial and trailing brackets have been removed already
    lines = model_text.splitlines()
    # print(len(lines))

    elements = parse_definitions(model_text)
    res = {}
    for e in elements:
        assert "define-fun" in e, f"no definition: {e}"
        tokens = tokenize(e)
        assert tokens[0] == "(", f"First token should be '(', is: {tokens[0]}"
        assert tokens[1] == "define-fun", f"Second token should be 'define-fun', is: {tokens[1]}"
        assert tokens[-1] == ")", f"Last token should be '(', is: {tokens[-1]}"
        name = tokens[2].strip()
        if tokens[3] == "(" and tokens[4] == ")": # empty arguments -> int value
            val: Union[int, DefaultDict] = to_int(tokens[-2].strip())
        else: # arguments -> ite -> dict
            val = parse_ite_definition(tokens, name)
        res.update({name : val})
    return res
