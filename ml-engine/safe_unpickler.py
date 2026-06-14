import io
import pickle
import pickletools

class SecurityError(ValueError):
    """Raised when pickle validation or unpickling fails security checks."""
    pass

# Whitelist allowed modules (base modules only)
ALLOWED_MODULES = {
    'numpy', 'lightgbm', 'sklearn', 'copyreg', 'collections', 'pandas', 'builtins'
}

# Whitelist allowed builtins
ALLOWED_BUILTINS = {
    'dict', 'list', 'set', 'tuple', 'int', 'float', 'str', 'bool'
}

class SafeUnpickler(pickle.Unpickler):
    """Subclass of pickle.Unpickler that restricts loaded modules and classes."""
    def find_class(self, module, name):
        base_module = module.split('.')[0]
        if base_module not in ALLOWED_MODULES:
            raise SecurityError(f"Forbidden module: {module}.{name}")
        
        if module == 'builtins' and name not in ALLOWED_BUILTINS:
            raise SecurityError(f"Forbidden builtin: {name}")
            
        return super().find_class(module, name)

def validate_pickle_safe(pkl_bytes: bytes):
    """Statically checks pickle byte stream for forbidden opcodes and modules."""
    try:
        stack = []
        for opcode, arg, pos in pickletools.genops(pkl_bytes):
            # Track pushed strings for stack-based global lookup
            if opcode.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE"):
                stack.append(arg)
            
            elif opcode.name == "GLOBAL":
                if isinstance(arg, tuple):
                    module, name = arg
                elif isinstance(arg, str):
                    parts = arg.split()
                    if len(parts) == 2:
                        module, name = parts
                    else:
                        module = arg
                        name = ""
                else:
                    raise SecurityError("Invalid GLOBAL opcode argument format")
                
                base_module = module.split('.')[0]
                if base_module not in ALLOWED_MODULES:
                    raise SecurityError(f"Forbidden GLOBAL module: {module}")
                
                if module == 'builtins' and name not in ALLOWED_BUILTINS:
                    raise SecurityError(f"Forbidden GLOBAL builtin: {name}")
            
            elif opcode.name == "STACK_GLOBAL":
                if len(stack) < 2:
                    raise SecurityError("Stack underflow on STACK_GLOBAL")
                name = stack.pop()
                module = stack.pop()
                
                base_module = module.split('.')[0]
                if base_module not in ALLOWED_MODULES:
                    raise SecurityError(f"Forbidden STACK_GLOBAL module: {module}")
                
                if module == 'builtins' and name not in ALLOWED_BUILTINS:
                    raise SecurityError(f"Forbidden STACK_GLOBAL builtin: {name}")
    except SecurityError as e:
        raise e
    except Exception as e:
        raise SecurityError(f"Failed to parse pickle: {e}")
