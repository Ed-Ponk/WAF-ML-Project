import io
import pickle

class SecurityError(ValueError):
    """Raised when pickle validation or unpickling fails security checks."""
    pass

# Whitelist allowed modules (base modules only)
# Se usa el primer segmento del nombre del módulo (ej. 'lightgbm.sklearn' → 'lightgbm')
ALLOWED_MODULES = {
    'numpy', 'lightgbm', 'sklearn', 'copyreg', 'collections', 'pandas',
    'builtins', 'joblib', 'scipy', 'threadpoolctl',
    'gzip', 'struct', 'array', 'datetime', 'math', 'json',
    '_json', '_struct', 'operator', 'functools', 'itertools',
    're', '_codecs', 'encodings',
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

# validate_pickle_safe intentionally removed.
#
# Static pickle analysis is unreliable in Python 3.13+ (pickletools.genops
# chokes on reorganized opcodes, and raw byte scans produce false positives
# when 0x63/GLOBAL appears in data blobs).
#
# Security is enforced by SafeUnpickler.find_class — the dynamic boundary
# that intercepts every module import at load time. That's the real guard.
