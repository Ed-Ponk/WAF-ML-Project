import pickle

from joblib.numpy_pickle import NumpyUnpickler

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

def _assert_allowed(module: str, name: str) -> None:
    base_module = module.split('.')[0]
    if base_module not in ALLOWED_MODULES:
        raise SecurityError(f"Forbidden module: {module}.{name}")

    if module == 'builtins' and name not in ALLOWED_BUILTINS:
        raise SecurityError(f"Forbidden builtin: {name}")

class SafeUnpickler(pickle.Unpickler):
    """pickle.Unpickler restringido a la whitelist. Para pickles planos.

    Los bundles del modelo usan el formato numpy_pickle de joblib, así que
    la carga segura de modelos pasa por SafeNumpyUnpickler / load_bundle_safe.
    """

    def find_class(self, module, name):
        _assert_allowed(module, name)
        return super().find_class(module, name)

class SafeNumpyUnpickler(NumpyUnpickler):
    """NumpyUnpickler de joblib + whitelist.

    Reconstruye los arrays numpy (NumpyArrayWrapper, bytes crudos embebidos,
    arrays grandes en .npy separado) exactamente igual que joblib.load, pero
    intercepta find_class para rechazar cualquier módulo/clase fuera de
    ALLOWED_MODULES.
    """

    def find_class(self, module, name):
        _assert_allowed(module, name)
        return super().find_class(module, name)

def load_bundle_safe(path: str):
    """Carga un bundle joblib (formato numpy_pickle) con el unpickler restringido.

    Detecta la compresión (gzip/bzip2/xz) por magic bytes igual que
    joblib.load; el bundle de producción es un pickle plano (PROTO >= 4).
    Lanza SecurityError si el archivo referencia un módulo/clase fuera de la
    whitelist, o pickle errors si el stream es inválido. El llamador decide
    si degradar; el modelo activo nunca se reemplaza por un archivo rechazado.
    """
    with open(path, "rb") as f:
        magic = f.read(6)
        f.seek(0)

        if magic.startswith(b"\x1f\x8b"):        # gzip
            import gzip
            handle = gzip.GzipFile(fileobj=f)
        elif magic.startswith(b"BZh"):           # bzip2
            import bz2
            handle = bz2.BZ2File(f)
        elif magic.startswith(b"\xfd7zXZ"):      # xz / lzma
            import lzma
            handle = lzma.LZMAFile(f)
        else:                                    # pickle plano
            handle = f

        return SafeNumpyUnpickler(path, handle, ensure_native_byte_order=True).load()

# validate_pickle_safe intentionally removed.
#
# Static pickle analysis is unreliable in Python 3.13+ (pickletools.genops
# chokes on reorganized opcodes, and raw byte scans produce false positives
# when 0x63/GLOBAL appears in data blobs).
#
# Security is enforced by find_class — the dynamic boundary that intercepts
# every module import at load time. That's the real guard.